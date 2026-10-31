#!/usr/bin/env bash
# boot.sh: bring every node to its rendered state (FRAMEWORK.md 3.3).
#
#   links         containers missing or an expected ethN gone (the host-reboot case): down fast,
#                 then up. Links are always redeployed, never adopted.
#   switches      in parallel, up to timeouts.switch_boot_s each: docker health healthy, the
#                 launcher's "KLISH startup config applied" line, SSH and show version.
#   parity        common/klish/parity.py against show running-configuration; missing lines are
#                 replayed with common/klish/replay.sh, then parity runs again. The launcher does
#                 not stop on "% Error", so parity is the only proof the file took.
#   gro           GRO, rx-gro-hw and LRO off on every data NIC inside every switch.
#   iccp          every pair member's iccpd listening on TCP 8888 in the domain's session VRF; a
#                 listener left in the default VRF (iccpd's bind failed at its start) is put right
#                 by restarting iccpd on that switch once, then read again.
#   fw            the PA-VM healthy, its delivered startup file identical to the render, the
#                 commit marker (else common/fw/fw-startup.py, fed to the container's own python
#                 with the render's sha256), and every
#                 line of bootstrap/fw/enforced.txt in the set-format running configuration.
#   ca            sfab-ca init on the lab host (common/ca/sfab-ca, outside every node), when the
#                 inventory turns ca_init on: the up stage made the CA before the deploy, and this run
#                 publishes the lab root, the node leaves and the Kubernetes intermediate under state/
#                 again (its key comes back after a retract); then, with the cluster on, the lab's
#                 kubeadm join token from state/secrets.env into state/shared/cluster/kubeadm.env
#                 (0600), never printed.
#   fabric        build A: show mclag brief and show PortChannel summary as rendered, in two
#                 consecutive polls 15 s apart (judge.py mclag-pair, the audit's own check). While
#                 the guests are held their bonds cannot be up, so this wait leaves out the
#                 PortChannels that face a guest, and those that face a storage node, whose data
#                 bond only finish's storage setup makes (truenas-setup.py).
#   release       remove state/shared/hold-guests; then every guest answers SSH and ran
#                 sfab-netsetup.service in this boot.
#   bonds         the pair again, now with the PortChannels that face the guests, in two
#                 consecutive polls: the guests' LACP bonds are up on both pair members. The storage
#                 nodes' PortChannels are still set aside; finish waits for them after the setup.
#   node-sync     common/host/node-sync.sh when present; exit 3 restarts sfab-cluster.service.
#   dns-zones     every secondary zone of every authoritative server the render makes one (its
#                 bootstrap/<node>/named.conf), by rndc zonestatus, loaded: a zone not loaded is told
#                 to transfer at once (rndc retransfer), since BIND backs a never-loaded zone's retries
#                 off while its primary is out of reach at boot (behind the firewall, which boots last)
#                 and can leave it unloaded many minutes after the path is up. Every 5 s, 300 s at most.
#
# Each step writes state/stage/boot.<step>.ok and is skipped while its marker matches.
# shellcheck disable=SC2317 # every step function runs through stage_step
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib.sh"
sfab_init boot "$@"

JUDGE="$SFAB_COMMON/audit/judge.py"
RUNDIR="$STATEDIR/run/boot"
mkdir -p "$RUNDIR"

boot_links() {
  if all_running && links_intact; then
    echo "boot: every container running with its links"
    return 0
  fi
  echo "boot: containers missing or links lost: redeploying (down fast, then up)"
  "$SFAB_COMMON/stages/down.sh" fast
  "$SFAB_COMMON/stages/up.sh"
}

# --- switches ------------------------------------------------------------------------------------

wait_switch() {
  local sw="$1" c deadline h
  c="$(ctr "$sw")"
  deadline=$((SECONDS + ${TO_SWITCH_BOOT_S:-1200}))
  until [ "$(health_of "$sw")" = healthy ]; do
    [ "$SECONDS" -lt "$deadline" ] || { echo "health $(health_of "$sw") after ${TO_SWITCH_BOOT_S:-1200}s"; return 1; }
    sleep 10
  done
  until dk logs "$c" 2>&1 | grep -qF 'KLISH startup config applied'; do
    [ "$SECONDS" -lt "$deadline" ] || { echo "no 'KLISH startup config applied' in the launcher log"; return 1; }
    sleep 10
  done
  until h="$(SW "$sw" "show version" 2>/dev/null)" && grep -q 'Version' <<<"$h"; do
    [ "$SECONDS" -lt "$deadline" ] || { echo "no show version over SSH"; return 1; }
    sleep 10
  done
  return 0
}

wait_switches() {
  local sw pids=() i rc fails=0
  sec "switches up"
  for sw in "${SWITCHES[@]}"; do
    (wait_switch "$sw" >"$RUNDIR/wait-$sw.txt" 2>&1; echo $? >"$RUNDIR/wait-$sw.rc") &
    pids+=("$!")
  done
  for i in "${pids[@]}"; do wait "$i" || true; done
  for sw in "${SWITCHES[@]}"; do
    rc="$(cat "$RUNDIR/wait-$sw.rc" 2>/dev/null || echo 1)"
    if [ "$rc" = 0 ]; then
      ok "$sw: healthy, KLISH startup config applied, show version over SSH"
    else
      bad "$sw: up" "$(tail -n 1 "$RUNDIR/wait-$sw.txt" 2>/dev/null)"
      fails=1
    fi
  done
  return "$fails"
}

# running_config SW FILE: show running-configuration, without the prompt line.
running_config() {
  SW "$1" "show running-configuration" | klish_body "show running-configuration" >"$2"
}

# parity_of SW: 0 clean, 1 missing lines (listed in $RUNDIR/parity-SW.missing), 2 an error.
parity_of() {
  local sw="$1" rendered="$RENDERDIR/bootstrap/$1/startup-config.cfg" norm=() rc=0
  [ ! -f "$RENDERDIR/gen/klish-normalize.json" ] || norm=(--normalize "$RENDERDIR/gen/klish-normalize.json")
  running_config "$sw" "$RUNDIR/running-$sw.txt" || return 2
  py "$SFAB_COMMON/klish/parity.py" "$rendered" "$RUNDIR/running-$sw.txt" --switch "$sw" "${norm[@]}" \
    --json "$RUNDIR/parity-$sw.json" >"$RUNDIR/parity-$sw.out" 2>"$RUNDIR/parity-$sw.err" || rc=$?
  grep -E '^ +missing \(' "$RUNDIR/parity-$sw.out" | sed 's/^ *//' >"$RUNDIR/parity-$sw.missing" || true
  return "$rc"
}

switch_parity() {
  local sw rc fails=0
  sec "parity"
  if [ ! -f "$SFAB_COMMON/klish/parity.py" ]; then
    skip "parity on ${#SWITCHES[@]} switches" "common/klish/parity.py is not present"
    return 3
  fi
  for sw in "${SWITCHES[@]}"; do
    rc=0
    parity_of "$sw" || rc=$?
    if [ "$rc" -eq 1 ]; then
      echo "boot: $sw misses $(grep -c . "$RUNDIR/parity-$sw.missing" || true) rendered lines; replaying them"
      if [ -x "$SFAB_COMMON/klish/replay.sh" ] && _creds "$sw"; then
        # replay.sh reads the render under SFAB_LABDIR and takes the switch password from its
        # environment: the one the switch container was given
        SFAB_LABDIR="$RENDERDIR" SFAB_SW_PASSWORD="$CRED_PASS" "$SFAB_COMMON/klish/replay.sh" "$sw" ||
          echo "boot: replay.sh $sw exited $? (3: a block of a live MCLAG domain was left alone)"
      else
        echo "boot: common/klish/replay.sh is not present"
      fi
      rc=0
      parity_of "$sw" || rc=$?
    fi
    case "$rc" in
      0) ok "$sw: parity, 0 missing lines" ;;
      1) bad "$sw: parity" "$(grep -c . "$RUNDIR/parity-$sw.missing" || true) lines still missing: $(head -n 2 "$RUNDIR/parity-$sw.missing" | paste -sd ';' -)"; fails=1 ;;
      *) bad "$sw: parity" "parity.py exited $rc: $(head -n 1 "$RUNDIR/parity-$sw.err" 2>/dev/null)"; fails=1 ;;
    esac
  done
  return "$fails"
}

gro_check() {
  local sw fails=0 probs
  sec "GRO off"
  for sw in "${SWITCHES[@]}"; do
    # The switch's admin login has no /usr/sbin on its PATH, so ethtool is named in full.
    # shellcheck disable=SC2016 # expanded by the switch's shell, not this one
    if ! SH "$sw" 'for i in $(ls /sys/class/net | grep "^eth[1-9][0-9]*$" | sort -V); do echo "== $i"; /usr/sbin/ethtool -k "$i" | grep -E "^(generic-receive-offload|rx-gro-hw|large-receive-offload):"; done' \
      >"$RUNDIR/gro-$sw.txt" 2>&1; then
      bad "$sw: GRO, rx-gro-hw and LRO off" "could not read ethtool"
      fails=1
      continue
    fi
    if probs="$(py "$JUDGE" offloads --nics "${NODE_NUM_NICS[$sw]}" "$RUNDIR/gro-$sw.txt")"; then
      ok "$sw: GRO, rx-gro-hw and LRO off on all ${NODE_NUM_NICS[$sw]} data NICs"
    else
      bad "$sw: GRO, rx-gro-hw and LRO off" "$(printf '%s' "$probs" | head -n 3 | paste -sd ';' -)"
      fails=1
    fi
  done
  return "$fails"
}

# iccp_vrf: from `ss -tanp` lines on stdin, the VRF of iccpd's listener on TCP 8888: "default" when
# it is bound to no device, nothing when there is no listener.
iccp_vrf() {
  awk '$1 == "LISTEN" && $4 ~ /:8888$/ { a = $4; sub(/:8888$/, "", a); if (a ~ /%/) { sub(/.*%/, "", a); print a } else print "default"; exit }'
}

# iccp_listen: on every pair member, iccpd's listener on TCP 8888 in the domain's session VRF.
# SONiC 4.6.0's iccpd binds its listening socket to the session VRF once, when it reads the domain;
# if the VRF's device does not take the bind then (iccpd.log: "Set socket SO_BINDTODEVICE option for
# server fd failed for vrf mgmt"), the listener stays in the default VRF for as long as iccpd runs,
# while its client sockets bind on a later try. The session still comes up, and the audit's
# pair-roles check then fails on the listener. A listener outside the VRF is put right by
# restarting iccpd on that switch, once, before the fabric wait, then read again.
iccp_listen() {
  local p a b sw want got was i fails=0
  sec "ICCP listener"
  for p in "${PAIRS[@]}"; do
    read -r a b <<<"${PAIR_MEMBERS[$p]}"
    for sw in $a $b; do
      want="$(inv get "nodes.$sw.mclag.session_vrf" 2>/dev/null || true)"
      want="${want:-default}" got=""
      for i in $(seq 1 "${TO_ICCP_POLLS:-24}"); do
        got="$(SH "$sw" "sudo ss -tanp | grep 8888" 2>/dev/null | iccp_vrf || true)"
        [ -z "$got" ] || break
        sleep "${TO_ICCP_POLL_S:-5}"
      done
      printf '%s\t%s\n' "$sw" "${got:-none}" >>"$RUNDIR/iccp-listen.tsv"
      if [ "$got" = "$want" ]; then
        ok "$sw: iccpd listens on TCP 8888 in VRF $want"
        continue
      fi
      if [ -z "$got" ]; then
        bad "$sw: iccpd listens on TCP 8888 in VRF $want" "no listener"
        fails=1
        continue
      fi
      was="$got" got=""
      echo "boot: $sw: iccpd's listener is in VRF $was, not $want; restarting iccpd"
      SH "$sw" "sudo systemctl restart iccpd" >/dev/null 2>&1 || true
      for i in $(seq 1 "${TO_ICCP_POLLS:-24}"); do
        sleep "${TO_ICCP_POLL_S:-5}"
        got="$(SH "$sw" "sudo ss -tanp | grep 8888" 2>/dev/null | iccp_vrf || true)"
        [ "$got" != "$want" ] || break
      done
      printf '%s\t%s\trestarted\n' "$sw" "${got:-none}" >>"$RUNDIR/iccp-listen.tsv"
      if [ "$got" = "$want" ]; then
        ok "$sw: iccpd listens on TCP 8888 in VRF $want (iccpd restarted: its listener was in VRF $was)"
      else
        bad "$sw: iccpd listens on TCP 8888 in VRF $want" "after a restart of iccpd: ${got:-no listener}"
        fails=1
      fi
    done
  done
  return "$fails"
}

# --- the firewall ----------------------------------------------------------------------------------

fw_committed() {
  local c
  c="$(ctr "$FW_NODE")"
  dk logs "$c" 2>&1 | grep -qF 'XML startup config commit finished: result=OK' && return 0
  dk exec "$c" test -f /tmp/lab-startup-committed 2>/dev/null
}

# fw_vpns: the tunnels' IKE gateways and IPsec tunnels from bootstrap/fw/vpn.json, set through the
# API and committed (render/panos.py VPN_PATH). Each gateway's pre-shared key comes from
# state/secrets/ipsec/<psk>.psk into a 0600 file the API call reads, removed at once; the key is
# never on a command line or printed.
fw_vpns() {
  local fw="$FW_NODE" plan="$RENDERDIR/bootstrap/$FW_NODE/vpn.json" api="$SFAB_COMMON/fw/fw-api.sh" n i what xpath file psk out
  [ -f "$plan" ] || return 0
  n="$(py -c 'import json, sys; print(len(json.load(open(sys.argv[1]))["steps"]))' "$plan")"
  for ((i = 0; i < n; i++)); do
    what="$(py -c 'import json, sys; print(json.load(open(sys.argv[1]))["steps"][int(sys.argv[2])]["what"])' "$plan" "$i")"
    xpath="$(py -c 'import json, sys; print(json.load(open(sys.argv[1]))["steps"][int(sys.argv[2])]["xpath"])' "$plan" "$i")"
    psk="$(py -c 'import json, sys; print(json.load(open(sys.argv[1]))["steps"][int(sys.argv[2])].get("psk") or "")' "$plan" "$i")"
    file="$(umask 077; mktemp "$RUNDIR/fw-vpn.XXXXXX")"
    if ! py - "$plan" "$i" "$STATEDIR/secrets/ipsec" "$file" <<'PY'
import json, os, sys
step = json.load(open(sys.argv[1]))["steps"][int(sys.argv[2])]
el = step["element"]
if step.get("psk"):
    f = os.path.join(sys.argv[3], step["psk"] + ".psk")
    key = open(f, encoding="utf-8").read().strip()
    if not key:
        sys.exit("empty pre-shared key file")
    el = el.replace(step["placeholder"], key)
with open(sys.argv[4], "w", encoding="utf-8") as fh:
    fh.write(el)
PY
    then
      rm -f "$file"
      bad "$fw: $what" "no pre-shared key ${psk:+$psk }in state/secrets/ipsec (make up's preflight makes it)"
      return 1
    fi
    out="$("$api" --lab "$RENDERDIR" set-file "$xpath" "$file" 2>&1)" || { rm -f "$file"; bad "$fw: $what set" "$out"; return 1; }
    rm -f "$file"
    ok "$fw: $what set through the API${psk:+, its key from state/secrets/ipsec}"
  done
  out="$("$api" --lab "$RENDERDIR" commit "sfab boot: tunnels" 2>&1)" || { bad "$fw: tunnels committed" "$(printf '%s' "$out" | tail -1)"; return 1; }
  ok "$fw: tunnels committed ($(printf '%s' "$out" | tail -1 | cut -c1-80))"
}

fw_bootstrap() {
  local fw="$FW_NODE" c rendered enforced deadline i miss
  c="$(ctr "$fw")"
  rendered="$RENDERDIR/bootstrap/$fw/startup-config.xml"
  enforced="$RENDERDIR/bootstrap/$fw/enforced.txt"
  sec "firewall $fw"
  deadline=$((SECONDS + ${TO_FW_HEALTHY_S:-1800}))
  local last="" same=0 now
  until [ "$(health_of "$fw")" = healthy ]; do
    [ "$SECONDS" -lt "$deadline" ] || { bad "$fw: healthy" "$(health_of "$fw") after ${TO_FW_HEALTHY_S:-1800}s"; return 1; }
    sleep 15
    # the launcher matches "Enter old password :" in one read; a kernel line printed in the
    # middle of the prompt splits it, and the launcher then waits on a console that is silent
    now="$(dk logs --tail 2 "$c" 2>&1 | tr -d '\r' | md5sum)"
    if [ "$now" = "$last" ]; then same=$((same + 15)); else same=0; last="$now"; fi
    if [ "$same" -ge 300 ] && dk logs --tail 6 "$c" 2>&1 | tr -d '\r' | grep -aq 'nter old password :'; then
      bad "$fw: healthy" "launcher silent for ${same}s at a first-login prompt split by a kernel line; make down and make up again"
      return 1
    fi
  done
  ok "$fw: healthy"
  if dk exec "$c" cat /config/startup-config.cfg 2>/dev/null | cmp -s - "$rendered"; then
    ok "$fw: delivered /config/startup-config.cfg matches the render byte for byte"
  else
    bad "$fw: delivered /config/startup-config.cfg matches the render" "differs from $(basename "$rendered") or is missing"
    return 1
  fi
  if fw_committed; then
    ok "$fw: startup configuration committed (marker present)"
  elif [ -f "$SFAB_COMMON/fw/fw-startup.py" ]; then
    echo "boot: no commit marker on $fw: running fw-startup.py inside the container"
    local sha
    sha="$(py -c 'import json, sys; print(json.load(open(sys.argv[1]))["files"][sys.argv[2]])' \
      "$RENDERDIR/gen/RENDER.json" "bootstrap/$fw/startup-config.xml" 2>/dev/null || true)"
    [ -n "$sha" ] || { bad "$fw: startup configuration committed" "no sha256 for the render in gen/RENDER.json"; return 1; }
    if dk exec -i "$c" /.venv/bin/python3 - --expect-sha256 "$sha" <"$SFAB_COMMON/fw/fw-startup.py" && fw_committed; then
      ok "$fw: startup configuration committed by fw-startup.py"
    else
      bad "$fw: startup configuration committed" "fw-startup.py did not leave the marker"
      return 1
    fi
  else
    bad "$fw: startup configuration committed" "no marker, and common/fw/fw-startup.py is not present"
    return 1
  fi
  if [ ! -f "$enforced" ]; then
    bad "$fw: enforced lines" "no rendered enforced.txt"
    return 1
  fi
  fw_vpns || return 1
  for i in $(seq 1 "${TO_FW_ENFORCED_TRIES:-3}"); do
    FW "set cli config-output-format set" "configure" "show" "exit" >"$RUNDIR/fw-set.txt" 2>&1 || true
    miss="$(py - "$enforced" "$RUNDIR/fw-set.txt" <<'PY'
import sys
norm = lambda s: " ".join(s.split())
have = {norm(l) for l in open(sys.argv[2], encoding="utf-8", errors="replace")}
want = [norm(l) for l in open(sys.argv[1], encoding="utf-8") if l.strip() and not l.lstrip().startswith("#")]
print(sum(1 for w in want if w not in have))
PY
)"
    if [ "$miss" = 0 ]; then
      ok "$fw: every enforced.txt line in the set-format running configuration (try $i)"
      return 0
    fi
    sleep "${TO_FW_ENFORCED_PAUSE_S:-20}"
  done
  bad "$fw: enforced lines" "$miss lines missing after ${TO_FW_ENFORCED_TRIES:-3} tries"
  return 1
}

ca_init() {
  sec "lab CA"
  # on the lab host, outside every node (common/ca/sfab-ca): idempotent, and it puts the Kubernetes
  # intermediate's key back in state/shared for the control nodes after a retract
  if "$SFAB_COMMON/ca/sfab-ca" -C "$RENDERDIR" init >"$RUNDIR/ca-init.txt" 2>&1; then
    ok "sfab-ca init on the lab host ($(grep -c '^  PASS ' "$RUNDIR/ca-init.txt") proof lines passed)"
  else
    bad "sfab-ca init on the lab host" "$(grep -m 1 -E '^  FAIL |FAIL:' "$RUNDIR/ca-init.txt" || tail -n 1 "$RUNDIR/ca-init.txt")"
    return 1
  fi
  [ "$STAGE_CLUSTER" = 1 ] || return 0
  join_token
}

# join_token: the lab's kubeadm token (state/secrets.env, made by preflight) where the Kubernetes
# guests read it, state/shared/cluster/kubeadm.env (0600). The init node creates it in the cluster
# with no expiry, and the joining nodes use it. Without this file the init node would make a token
# of its own, which the transcripts' redaction (state/secrets.env) would not know.
join_token() {
  local f="$STATEDIR/shared/cluster/kubeadm.env" t
  t="$(sed -n 's/^SFAB_KUBEADM_TOKEN=//p' "$STATEDIR/secrets.env" 2>/dev/null | tail -n 1)"
  if ! [[ $t =~ ^[a-z0-9]{6}\.[a-z0-9]{16}$ ]]; then
    bad "the kubeadm join token for the guests" "state/secrets.env holds no SFAB_KUBEADM_TOKEN of the form [a-z0-9]{6}.[a-z0-9]{16}"
    return 1
  fi
  mkdir -p "$(dirname "$f")"
  if [ "$(cat "$f" 2>/dev/null || true)" != "SFAB_KUBEADM_TOKEN=$t" ]; then
    (umask 077 && printf 'SFAB_KUBEADM_TOKEN=%s\n' "$t" >"$f.sfab-new" && mv -f "$f.sfab-new" "$f")
  fi
  chmod 0600 "$f"
  ok "the lab's kubeadm join token in state/shared/cluster/kubeadm.env (0600, from state/secrets.env)"
}

# --- the fabric ------------------------------------------------------------------------------------

# fabric_poll DIR [EXCEPT]: read the pairs into a scratch result set and judge them; 0 when all
# hold. EXCEPT (comma-separated nodes) leaves out the PortChannels that face those nodes.
fabric_poll() {
  local dir="$1" except="${2:-}" p a b sw rc=0
  rm -rf "$dir"
  for p in "${PAIRS[@]}"; do
    read -r a b <<<"${PAIR_MEMBERS[$p]}"
    for sw in "$a" "$b"; do
      mkdir -p "$dir/$sw"
      SW "$sw" "show mclag brief" "show PortChannel summary" >"$dir/$sw.session" 2>/dev/null || true
      printf '01\tmclag_brief\tklish\t.txt\tshow mclag brief\n02\tportchannel_summary\tklish\t.txt\tshow PortChannel summary\n' >"$dir/$sw.plan"
      py "$JUDGE" split --style klish --plan "$dir/$sw.plan" --session "$dir/$sw.session" --out "$dir/$sw" >/dev/null || true
    done
    SFAB_VERDICT="$dir/verdict-$p.txt" py "$JUDGE" run --set "$dir" --inv "$INV" --render "$RENDERDIR" \
      --except-peers "$except" mclag-pair "$a" "$b" >"$dir/judge-$p.txt" 2>&1 || rc=1
  done
  return "$rc"
}

# pair_wait LABEL DIR [EXCEPT]: fabric_poll until it holds in TO_FABRIC_CONSECUTIVE polls in a row.
pair_wait() {
  local label="$1" dir="$2" except="${3:-}"
  local polls=${TO_FABRIC_POLLS:-120} pause=${TO_FABRIC_POLL_S:-15} need=${TO_FABRIC_CONSECUTIVE:-2} good=0 i p
  for i in $(seq 1 "$polls"); do
    if fabric_poll "$dir" "$except"; then
      good=$((good + 1))
      [ "$good" -ge "$need" ] && break
    else
      good=0
    fi
    sleep "$pause"
  done
  if [ "$good" -lt "$need" ]; then
    for p in "${PAIRS[@]}"; do
      grep -E '^  FAIL  ' "$dir/judge-$p.txt" 2>/dev/null | head -n 5 | sed 's/^  FAIL  /        last poll: /' || true
    done
  fi
  if [ "$good" -ge "$need" ]; then
    ok "$label in $need consecutive polls ${pause}s apart (poll $i)"
  else
    bad "$label" "not $need clean polls in a row within $polls polls"
    return 1
  fi
}

# The guests' bonds cannot come up while the guests are held, so the fabric wait before the
# release leaves out the PortChannels that face a guest; wait_bonds checks them after it. A storage
# node's data bond is made by its setup in finish (truenas-setup.py), so both waits leave out the
# PortChannels that face a storage node; finish's storage step waits for them.
storage_except() { [ ${#STORAGE[@]} -eq 0 ] || (IFS=,; printf '%s' "${STORAGE[*]}"); }

wait_fabric() {
  local except="" stor label
  sec "fabric"
  case "$WAIT_FABRIC" in
    mclag) ;;
    none) ok "no fabric condition to wait for"; return 0 ;;
    *) skip "wait_fabric $WAIT_FABRIC" "no hold condition for this fabric yet"; return 3 ;;
  esac
  if [ "$STAGE_GUEST_HOLD" = 1 ] && [ ${#GUESTS[@]} -gt 0 ]; then except="$(IFS=,; printf '%s' "${GUESTS[*]}")"; fi
  stor="$(storage_except)"
  label="pair session, roles, peer link and PortChannels as rendered"
  [ -z "$except" ] || label="$label, the PortChannels facing the held guests set aside until their release"
  [ -z "$stor" ] || label="$label, the storage bonds set aside until finish's storage setup"
  pair_wait "$label" "$RUNDIR/fabric" "$except${except:+${stor:+,}}$stor"
}

wait_bonds() {
  local stor label="pair session, roles and every PortChannel as rendered, the guest bonds included"
  sec "guest bonds"
  [ "$WAIT_FABRIC" = mclag ] || { ok "no pair to hold the guests' bonds"; return 0; }
  stor="$(storage_except)"
  [ -z "$stor" ] || label="$label, the storage bonds set aside until finish's storage setup"
  pair_wait "$label" "$RUNDIR/bonds" "$stor"
}

# --- the guests ------------------------------------------------------------------------------------

release_guests() {
  sec "guests"
  if [ -f "$STATEDIR/shared/hold-guests" ]; then
    rm -f "$STATEDIR/shared/hold-guests"
    ok "guests released (state/shared/hold-guests removed)"
  else
    ok "guests not held"
  fi
}

wait_guest() {
  local g="$1" deadline out
  deadline=$((SECONDS + ${SFAB_GUEST_WAIT_S:-1800}))
  while :; do
    if out="$(EVID_OFF=1 H "$g" "systemctl show -p Result -p ExecMainStatus -p ExecMainExitTimestampMonotonic sfab-netsetup.service" 2>/dev/null)"; then
      if grep -qx 'Result=success' <<<"$out" && grep -qx 'ExecMainStatus=0' <<<"$out" &&
        ! grep -qx 'ExecMainExitTimestampMonotonic=0' <<<"$out"; then
        return 0
      fi
    fi
    [ "$SECONDS" -lt "$deadline" ] || { echo "after ${SFAB_GUEST_WAIT_S:-1800}s: ${out:-no SSH}" | tr '\n' ' '; return 1; }
    sleep 10
  done
}

wait_guests() {
  local g pids=() i rc fails=0
  for g in "${GUESTS[@]}"; do
    (wait_guest "$g" >"$RUNDIR/guest-$g.txt" 2>&1; echo $? >"$RUNDIR/guest-$g.rc") &
    pids+=("$!")
  done
  for i in "${pids[@]}"; do wait "$i" || true; done
  for g in "${GUESTS[@]}"; do
    rc="$(cat "$RUNDIR/guest-$g.rc" 2>/dev/null || echo 1)"
    if [ "$rc" = 0 ]; then ok "$g: SSH answers and sfab-netsetup.service ran in this boot"; else bad "$g: up" "$(tail -n 1 "$RUNDIR/guest-$g.txt")"; fails=1; fi
  done
  return "$fails"
}

node_sync() {
  local tool="$SFAB_COMMON/host/node-sync.sh" rc=0 init
  sec "node sync"
  if [ ! -x "$tool" ]; then
    skip "node-sync" "common/host/node-sync.sh is not present"
    return 3
  fi
  "$tool" || rc=$?
  case "$rc" in
    0) ok "guests' boot-time files match the repo" ;;
    3)
      ok "guests' boot-time files updated from the repo"
      if [ "$STAGE_CLUSTER" = 1 ]; then
        for init in "${GUESTS[@]}"; do
          [ "${NODE_K8S[$init]}" = init ] || continue
          H "$init" "systemctl restart sfab-cluster.service" >/dev/null && ok "$init: sfab-cluster.service restarted"
        done
      fi ;;
    *) bad "node-sync" "exited $rc"; return 1 ;;
  esac
}

# --- the secondary DNS zones ------------------------------------------------------------------------

# secondary_zones: "<node> <view> <zone>" for every type secondary zone in a rendered named.conf
secondary_zones() {
  local f n
  for f in "$RENDERDIR"/bootstrap/*/named.conf; do
    [ -f "$f" ] || continue
    n="$(basename "$(dirname "$f")")"
    [ -n "${NODE_KIND[$n]:-}" ] || continue
    awk -v n="$n" '
      /^[[:space:]]*view[[:space:]]+"/ { v = $2; gsub(/"/, "", v) }
      /zone[[:space:]]+"[^"]+"[[:space:]]*\{[^}]*type[[:space:]]+secondary/ {
        z = $0; sub(/.*zone[[:space:]]+"/, "", z); sub(/".*/, "", z); print n, (v == "" ? "_default" : v), z }' "$f"
  done
}

dns_zones() {
  local plan n v z i got how fails=0 left
  sec "secondary DNS zones"
  plan="$(secondary_zones)"
  if [ -z "$plan" ]; then ok "no secondary DNS zone in this lab"; return 0; fi
  while read -r n v z; do
    [ -n "$n" ] || continue
    got="" how="by transfer"
    for i in $(seq 1 60); do
      got="$(EVID_OFF=1 X "$n" rndc -k /run/named/rndc.key zonestatus "$z" IN "$v" 2>/dev/null | sed -n 's/^serial: //p')"
      [ -z "$got" ] || break
      if [ $((i % 12)) = 1 ]; then
        EVID_OFF=1 X "$n" rndc -k /run/named/rndc.key retransfer "$z" IN "$v" >/dev/null 2>&1 || true
        how="by rndc retransfer"
      fi
      sleep 5
    done
    if [ -n "$got" ]; then
      ok "$n: view $v's secondary zone $z loaded at serial $got ($how)"
    else
      bad "$n: view $v's secondary zone $z loaded" "not loaded after 300 s, rndc retransfer sent"; fails=1
    fi
  done <<<"$plan"
  return "$fails"
}

# --- the order -------------------------------------------------------------------------------------

rc=0
boot_links
if [ ${#SWITCHES[@]} -gt 0 ]; then
  stage_step boot switches wait_switches || rc=1
  [ "$rc" -ne 0 ] || stage_step boot parity switch_parity || rc=1
  [ "$rc" -ne 0 ] || stage_step boot gro gro_check || rc=1
  if [ "$rc" -eq 0 ] && [ ${#PAIRS[@]} -gt 0 ]; then stage_step boot iccp iccp_listen || rc=1; fi
fi
if [ "$rc" -eq 0 ] && [ -n "$FW_NODE" ] && [ "$STAGE_FW_BOOTSTRAP" = 1 ]; then stage_step boot fw fw_bootstrap || rc=1; fi
if [ "$rc" -eq 0 ] && [ "$STAGE_CA_INIT" = 1 ]; then stage_step boot ca ca_init || rc=1; fi
if [ "$rc" -eq 0 ] && [ ${#PAIRS[@]} -gt 0 ]; then stage_step boot fabric wait_fabric || rc=1; fi
if [ "$rc" -eq 0 ] && [ ${#GUESTS[@]} -gt 0 ]; then
  release_guests
  stage_step boot guests wait_guests || rc=1
  if [ "$rc" -eq 0 ] && [ ${#PAIRS[@]} -gt 0 ]; then stage_step boot bonds wait_bonds || rc=1; fi
  [ "$rc" -ne 0 ] || stage_step boot node-sync node_sync || rc=1
fi
[ "$rc" -ne 0 ] || stage_step boot dns-zones dns_zones || rc=1
summary || rc=1
exit "$rc"
