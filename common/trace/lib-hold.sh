# shellcheck shell=bash
# common/trace/lib-hold.sh: chapter 10's session measurement, recorded as audits/<lab>_hold_<UTC>/
# with HOLD.md, verdict.txt, the held connections' events and the firewall's reads. A chapter's
# hold.sh is
#
#   . "$(dirname "$0")/../common/lib.sh"; sfab_init hold "$@"
#   . "$SFAB_COMMON/trace/lib-hold.sh"; hold_run
#
# The plan is gen/tenancy.json's hold section (sfab.render.tenancy, chapter.yaml tenancy.hold). In
# order: each zone's session count and show session info read before the load; every population's
# held connections started at once (common/trace/hold_conns.py in its client: N keep-alive HTTPS
# connections to its own Gateway's test backend, each used again every every_s for hold_s); once
# every client reports its connections held, each zone's count and show session info read again;
# one chat completion per population with its own caller's key (the transcript off around the
# key's hand-over); the counts read once more; the connections kept until each client ends its own
# load at hold_s (hold_end, so the run holds them as long as the plan says), the load stopped and the
# counts read after it. Then holdrun.py judges the files and writes HOLD.md, with the Little's law
# arithmetic per zone.
#
# Changes nothing on any device; every process it starts it stops, and the files it leaves under
# /tmp in the clients it removes.

# shellcheck source=common/audit/lib-tenancy.sh
. "$SFAB_COMMON/audit/lib-tenancy.sh"

hold_run() {
  local d rows i stamp_args=() factor="${HOLD_FACTOR:-1}" n t0
  tn_has hold || die "hold: gen/tenancy.json holds no hold plan (chapter.yaml tenancy.hold, or make render)"
  [ -n "${FW_NODE:-}" ] || die "hold: the lab has no firewall"
  d="$RS"
  cp "$TN_PLAN" "$d/tenancy.json"
  trap hold_cleanup EXIT
  rows="$(tn_get hold.rows | grep -c .)"
  n=$(($(tn_get hold.n) * factor))
  sec "the held connections: $n a population, held $(tn_get hold.hold_s) s, each used again every $(tn_get hold.every_s) s"
  hold_counts "$d" before
  t0="$(date +%s)"
  for ((i = 0; i < rows; i++)); do hold_start "$d" "$i" "$n" "$(tn_get hold.hold_s)"; done
  for ((i = 0; i < rows; i++)); do hold_wait "$d" "$i" 120 || true; done
  date +%s.%N >"$d/held-at.txt"
  hold_counts "$d" held
  for ((i = 0; i < rows; i++)); do hold_chat "$d" "$i"; done
  hold_counts "$d" chat
  for ((i = 0; i < rows; i++)); do hold_end "$d" "$i" "$((t0 + $(tn_get hold.hold_s) + ${SFAB_HOLD_GRACE_S:-60}))" || true; done
  for ((i = 0; i < rows; i++)); do hold_stop "$d" "$i"; done
  date +%s.%N >"$d/stopped-at.txt"
  sleep "${SFAB_HOLD_AFTER_S:-5}"
  hold_counts "$d" after
  trap - EXIT
  [ -z "${SFAB_TICK_STAMP:-}" ] || stamp_args=(--stamp "$SFAB_TICK_STAMP")
  py "$SFAB_COMMON/trace/holdrun.py" judge --set "$d" --plan "$TN_PLAN" --factor "$factor" "${stamp_args[@]+"${stamp_args[@]}"}" || true
  summary
}

# hold_end DIR ROW DEADLINE: wait until the row's client reports its load done (hold_conns.py ends it
# itself at hold_s), until the epoch second DEADLINE at most; the stop file is the harness's only
# after that
hold_end() {
  local d="$1" i="$2" until="$3" pop
  pop="$(hold_field "$i" population)"
  while [ "$(date +%s)" -lt "$until" ]; do
    grep -q '"event": "done"' "$d/hold-$pop.jsonl" 2>/dev/null && return 0
    kill -0 "${HOLD_PIDS[$i]:-0}" 2>/dev/null || return 0
    sleep 1
  done
  warn "hold: $pop did not end its load by itself within its hold"
  return 1
}
