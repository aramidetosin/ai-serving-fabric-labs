# shellcheck shell=bash
# common/reads/rpf.sh: how Linux combines the all and per-interface rp_filter values, shown on the
# relay's cross-rail flow (book Chapter 5, "Cross-Rail Relay with PXN and IP Routes"), sourced by a
# lab's rpf.sh after sfab_init.
#
# The flow is the trace's cross-rail one (gen/trace.json): from k8s-gpu1's namespace gpu1 (10.21.1.11)
# to k8s-gpu2's address on rail 2 (10.21.2.12). The request reaches k8s-gpu2's namespace gpu2 on its macvlan
# rail2, while that namespace's route back to 10.21.1.0/24 points at the relay, so a strict reverse
# path check on rail2 would drop it. The kernel's ip-sysctl.rst says the max of conf/all/rp_filter
# and conf/<interface>/rp_filter is used for source validation on the interface. In the receiving
# namespace the stage reads all, default, rail2 and relay rp_filter and the kernel's reverse-path
# drop counter (IPReversePathFilter, read with nstat inside the namespace), then runs three cases,
# each a short cross-rail ping with the counter read before and after it:
#
#   a  as built: all 2, rail2 2           answered, the counter unchanged
#   b  all 1, rail2 0                     dropped, the counter rises: the interface's 0 cannot
#                                         lower the effective mode below all's 1 (strict)
#   c  all 1, rail2 2                     answered: the max is 2 (loose)
#
# then puts back the values it read as built, reads them again and pings once more. The values are
# put back on any exit (a trap). Each read is saved as <case>/<n>-<what>.txt in the shell form a
# reader types (the prompt line, then the output).

# Build A revision 2: the relay is labeled wherever it is shown.
RPF_LABEL="the IP relay between rails is the lab's stand-in that lets captures show PXN's path: production GPU hosts do not IP-forward between rails (NCCL moves cross-rail collective data over NVLink with PXN, and its IP control traffic uses the frontend), and rp_filter 2 belongs to the relay; production keeps 1 with per-rail policy routing"
RPF_COUNT="${RPF_COUNT:-3}"
RPF_IV="${RPF_IV:-0.2}"

# rpf_pick: the cross-rail flow and the receiving namespace's names (gen/trace.json and the far
# node's node.env)
rpf_pick() {
  local out
  out="$(py - "$RENDERDIR/gen/trace.json" "$RENDERDIR/bootstrap" <<'PY'
import json, shlex, sys
plan, boot = json.load(open(sys.argv[1])), sys.argv[2]
f = next(x for x in plan["flows"] if x["kind"] == "cross")
env = {}
for line in open(f"{boot}/{f['dst_node']}/node.env"):
    if "=" in line and not line.startswith("#"):
        k, v = line.rstrip("\n").split("=", 1)
        env[k] = (shlex.split(v) or [""])[0]
r = f["to_rail"]
print(f["src_node"], f["src_ns"], f["src_addr"], f["dst_node"], f["dst_addr"], env[f"RELAY{r}_NS"], env[f"RELAY{r}_MACVLAN"],
      env[f"RELAY{r}_VETH"], f["rail"], r)
PY
)" || return 1
  read -r RPF_SRC RPF_SRC_NS RPF_SRC_ADDR RPF_DST RPF_DST_ADDR RPF_NS RPF_RAIL_IF RPF_RELAY_IF RPF_FROM_RAIL RPF_TO_RAIL <<<"$out"
}

# rpf_read DIR NAME NODE CMD: run CMD as root in the node's guest, save the prompt line a reader
# types (sudo at the login user's prompt) and the output as DIR/NAME.txt; prints the output
rpf_read() {
  local dir="$1" name="$2" node="$3" cmd="$4" f
  mkdir -p "$RS/$dir"
  f="$RS/$dir/$name.txt"
  { printf '%s@%s:~$ sudo %s\n' "$GUEST_USER" "$node" "$cmd"; H "$node" "$cmd" 2>&1 || true; } >"$f"
  tail -n +2 "$f"
}

rpf_sysctl_names() {
  printf 'net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter net.ipv4.conf.%s.rp_filter net.ipv4.conf.%s.rp_filter' \
    "$RPF_RAIL_IF" "$RPF_RELAY_IF"
}

# rpf_value DIR/NAME KEY: a value from a saved sysctl read ("key = value" lines)
rpf_value() { tail -n +2 "$RS/$1.txt" | awk -v k="$2" '$1 == k && $2 == "=" { print $3; exit }' || true; }

# rpf_values DIR LABEL ALL RAIL: read the four values; PASS when all and the rail's are as wanted
# (the relay's stays as built)
rpf_values() {
  local dir="$1" n="$2" all="$3" rail="$4" a r d l
  rpf_read "$dir" "$n-values" "$RPF_DST" "ip netns exec $RPF_NS sysctl $(rpf_sysctl_names)" >/dev/null
  a="$(rpf_value "$dir/$n-values" net.ipv4.conf.all.rp_filter)"
  d="$(rpf_value "$dir/$n-values" net.ipv4.conf.default.rp_filter)"
  r="$(rpf_value "$dir/$n-values" "net.ipv4.conf.$RPF_RAIL_IF.rp_filter")"
  l="$(rpf_value "$dir/$n-values" "net.ipv4.conf.$RPF_RELAY_IF.rp_filter")"
  if [ "$a" = "$all" ] && [ "$r" = "$rail" ]; then
    ok "$RPF_DST, namespace $RPF_NS: all $a, $RPF_RAIL_IF $r (default $d, $RPF_RELAY_IF $l)"
  else
    bad "$RPF_DST, namespace $RPF_NS: all $all, $RPF_RAIL_IF $rail" "all ${a:-?}, $RPF_RAIL_IF ${r:-?}"
  fi
}

# rpf_counter DIR NAME: the namespace's IPReversePathFilter count, saved; prints the number
rpf_counter() {
  rpf_read "$1" "$2" "$RPF_DST" "ip netns exec $RPF_NS nstat -asz TcpExtIPReversePathFilter" >/dev/null
  tail -n +2 "$RS/$1/$2.txt" | awk '$1 == "TcpExtIPReversePathFilter" { print $2; exit }' || true
}

# rpf_ping DIR NAME: the cross-rail ping, saved; prints how many replies came back
rpf_ping() {
  rpf_read "$1" "$2" "$RPF_SRC" "ip netns exec $RPF_SRC_NS ping -q -c $RPF_COUNT -i $RPF_IV -W 1 $RPF_DST_ADDR" >/dev/null
  tail -n +2 "$RS/$1/$2.txt" | sed -n 's/.* \([0-9][0-9]*\) received.*/\1/p' | head -n 1
}

# rpf_set DIR NAME ALL RAIL: write all and the rail interface's value in the receiving namespace
rpf_set() {
  rpf_read "$1" "$2" "$RPF_DST" "ip netns exec $RPF_NS sysctl -w net.ipv4.conf.all.rp_filter=$3 net.ipv4.conf.$RPF_RAIL_IF.rp_filter=$4" >/dev/null
}

# rpf_case DIR TITLE ALL RAIL WANT: set (unless the values are as built), read, count, ping, count;
# WANT is answered or dropped
rpf_case() {
  local dir="$1" title="$2" all="$3" rail="$4" want="$5" n=1 c0 c1 got rise
  sec "$title"
  if [ "$all/$rail" != "$RPF_ALL0/$RPF_RAIL0" ]; then rpf_set "$dir" "$n-set" "$all" "$rail"; n=$((n + 1)); fi
  rpf_values "$dir" "$n" "$all" "$rail"
  n=$((n + 1))
  c0="$(rpf_counter "$dir" "$n-counter-before")"
  n=$((n + 1))
  got="$(rpf_ping "$dir" "$n-ping")"
  n=$((n + 1))
  c1="$(rpf_counter "$dir" "$n-counter-after")"
  if [[ "$c0" =~ ^[0-9]+$ ]] && [[ "$c1" =~ ^[0-9]+$ ]]; then rise=$((c1 - c0)); else rise="?"; fi
  if [ "$want" = answered ]; then
    chk "$RPF_SRC $RPF_SRC_NS to $RPF_DST_ADDR (rail $RPF_FROM_RAIL to rail $RPF_TO_RAIL): $RPF_COUNT of $RPF_COUNT answered" "$RPF_COUNT" "${got:-?}"
    chk "IPReversePathFilter in $RPF_DST's namespace $RPF_NS unchanged ($c0 before, $c1 after)" 0 "$rise"
  else
    chk "$RPF_SRC $RPF_SRC_NS to $RPF_DST_ADDR (rail $RPF_FROM_RAIL to rail $RPF_TO_RAIL): none of $RPF_COUNT answered" 0 "${got:-?}"
    ge "IPReversePathFilter in $RPF_DST's namespace $RPF_NS rose by at least $RPF_COUNT ($c0 before, $c1 after)" "$RPF_COUNT" "$rise"
  fi
}

# rpf_restore: the values read as built, written back (the trap runs it on any exit)
rpf_restore() {
  [ -n "${RPF_ALL0:-}" ] && [ -n "${RPF_RAIL0:-}" ] || return 0
  H "$RPF_DST" "ip netns exec $RPF_NS sysctl -qw net.ipv4.conf.all.rp_filter=$RPF_ALL0 net.ipv4.conf.$RPF_RAIL_IF.rp_filter=$RPF_RAIL0" \
    >/dev/null 2>&1 || warn "could not put back rp_filter in $RPF_DST's namespace $RPF_NS (all $RPF_ALL0, $RPF_RAIL_IF $RPF_RAIL0)"
}

rpf_run() {
  local want
  rpf_pick || { bad "rpf: the cross-rail flow from gen/trace.json" "cannot read it"; summary; return; }
  want="$(inv get "nodes.$RPF_DST.relay.rp_filter" 2>/dev/null || echo 2)"
  printf 'from: %s namespace %s (%s)\nto: %s on rail %s (%s namespace %s, %s)\nrelay: %s\ncount: %s\nlabel: %s\n' \
    "$RPF_SRC" "$RPF_SRC_NS" "$RPF_SRC_ADDR" "$RPF_DST_ADDR" "$RPF_TO_RAIL" "$RPF_DST" "$RPF_NS" "$RPF_RAIL_IF" "$RPF_RELAY_IF" "$RPF_COUNT" \
    "$RPF_LABEL" >"$RS/FOLLOWED.txt"
  echo "rpf: $RPF_LABEL"
  sec "rp_filter on $RPF_DST's namespace $RPF_NS: the cross-rail request from $RPF_SRC_ADDR arrives on $RPF_RAIL_IF, its route back leaves on $RPF_RELAY_IF"
  rpf_read built 1-route-back "$RPF_DST" "ip -n $RPF_NS route get $RPF_SRC_ADDR from $RPF_DST_ADDR" >/dev/null
  if tail -n +2 "$RS/built/1-route-back.txt" | grep -q " dev $RPF_RELAY_IF "; then
    ok "$RPF_NS's route back to $RPF_SRC_ADDR leaves on $RPF_RELAY_IF, not on $RPF_RAIL_IF where the request arrives"
  else
    bad "$RPF_NS's route back to $RPF_SRC_ADDR leaves on $RPF_RELAY_IF" "$(tail -n +2 "$RS/built/1-route-back.txt" | head -n 1)"
  fi
  rpf_read built 2-values "$RPF_DST" "ip netns exec $RPF_NS sysctl $(rpf_sysctl_names)" >/dev/null
  RPF_ALL0="$(rpf_value built/2-values net.ipv4.conf.all.rp_filter)"
  RPF_RAIL0="$(rpf_value built/2-values "net.ipv4.conf.$RPF_RAIL_IF.rp_filter")"
  chk "as built, all is $want (loose), the render's value" "$want" "${RPF_ALL0:-?}"
  chk "as built, $RPF_RAIL_IF is $want" "$want" "${RPF_RAIL0:-?}"
  chk "as built, $RPF_RELAY_IF is $want" "$want" "$(rpf_value built/2-values "net.ipv4.conf.$RPF_RELAY_IF.rp_filter")"
  chk "as built, default is $want" "$want" "$(rpf_value built/2-values net.ipv4.conf.default.rp_filter)"
  if [ "$RPF_ALL0" != "$want" ] || [ "$RPF_RAIL0" != "$want" ]; then
    RPF_ALL0="" RPF_RAIL0=""
    summary
    return
  fi
  trap rpf_restore EXIT
  rpf_case case-a "case a, as built: all $RPF_ALL0, $RPF_RAIL_IF $RPF_RAIL0 (loose): the request is answered" "$RPF_ALL0" "$RPF_RAIL0" answered
  rpf_case case-b "case b: all 1, $RPF_RAIL_IF 0: the max is 1 (strict), so the request is dropped" 1 0 dropped
  rpf_case case-c "case c: all 1, $RPF_RAIL_IF 2: the max is 2 (loose), so the request is answered" 1 2 answered
  sec "restored: all $RPF_ALL0, $RPF_RAIL_IF $RPF_RAIL0, as built"
  rpf_set restored 1-set "$RPF_ALL0" "$RPF_RAIL0"
  rpf_values restored 2 "$RPF_ALL0" "$RPF_RAIL0"
  trap - EXIT
  chk "$RPF_SRC $RPF_SRC_NS to $RPF_DST_ADDR: $RPF_COUNT of $RPF_COUNT answered again" "$RPF_COUNT" "$(rpf_ping restored 3-ping)"
  summary
}
