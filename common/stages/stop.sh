#!/usr/bin/env bash
# stop.sh: power the lab's VMs off cleanly, in order (FRAMEWORK.md 3.5).
#
# First every lab container gets `docker update --restart=no` (belt and braces: guests are
# rendered with restart-policy "no" already). Then:
#   1. GPU guests powered off from inside (systemctl poweroff), up to timeouts.stop_gpu_s;
#   2. storage: TrueNAS with docker stop -t timeouts.stop_storage_s (QEMU gets ACPI); ONTAP halted
#      from its own CLI first;
#   3. the other guests (the control plane), up to timeouts.stop_control_s.
# A guest still running at its deadline is stopped with docker stop. docker stop alone gives a
# QEMU guest no ACPI signal, so it is never the first resort for a VM guest. Switches and the
# firewall are left to down.sh.
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib.sh"
sfab_init stop "$@"

no_restart() {
  local c n=0
  while read -r c; do
    [ -n "$c" ] || continue
    dk update --restart=no "$c" >/dev/null && n=$((n + 1))
  done < <(lab_containers)
  echo "stop: restart policy off on $n containers"
}

# power_off LABEL DEADLINE_S NODE...: poweroff inside each running guest, wait, then docker stop.
power_off() {
  local label="$1" wait_s="$2" g up=() left=() deadline
  shift 2
  for g in "$@"; do running "$g" && up+=("$g"); done
  if [ ${#up[@]} -eq 0 ]; then echo "stop: $label: none running"; return 0; fi
  echo "stop: $label: powering off ${up[*]}"
  for g in "${up[@]}"; do EVID_OFF=1 H "$g" "systemctl --no-block poweroff" >/dev/null 2>&1 || echo "stop: $g did not take the poweroff over SSH"; done
  deadline=$((SECONDS + wait_s))
  while :; do
    left=()
    for g in "${up[@]}"; do running "$g" && left+=("$g"); done
    [ ${#left[@]} -gt 0 ] || break
    [ $SECONDS -lt "$deadline" ] || break
    sleep 5
  done
  if [ ${#left[@]} -gt 0 ]; then
    echo "stop: $label: still running after ${wait_s}s, docker stop: ${left[*]}"
    for g in "${left[@]}"; do dk stop -t 30 "$(ctr "$g")" >/dev/null || true; done
  fi
  echo "stop: $label: off"
}

stop_storage() {
  local s
  for s in "${STORAGE[@]}"; do
    running "$s" || continue
    case "${NODE_KIND[$s]}" in
      ontap)
        if _creds "$s"; then
          echo "stop: halting $s from its CLI"
          _CAP_SSHPASS="$CRED_PASS" _cap "$s" ontap-cli "system node halt" timeout 120 sshpass -e ssh "${_SSH_PW[@]}" \
            "$CRED_USER@$(node_mgmt "$s")" "set -confirmations off; system node halt -node * -inhibit-takeover true -ignore-quorum-warnings true" \
            >/dev/null 2>&1 || echo "stop: $s halt over SSH failed"
          sleep 30
        fi ;;
    esac
    echo "stop: $s: docker stop -t ${TO_STOP_STORAGE_S:-120}"
    dk stop -t "${TO_STOP_STORAGE_S:-120}" "$(ctr "$s")" >/dev/null || true
  done
}

no_restart
others=()
for g in "${GUESTS[@]}"; do
  [[ " ${GPU_GUESTS[*]} " == *" $g "* ]] || others+=("$g")
done
power_off "GPU guests" "${TO_STOP_GPU_S:-300}" "${GPU_GUESTS[@]}"
stop_storage
power_off "control plane" "${TO_STOP_CONTROL_S:-180}" "${others[@]}"
