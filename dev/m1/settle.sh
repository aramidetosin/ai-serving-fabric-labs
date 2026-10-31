#!/usr/bin/env bash
# dev/m1/settle.sh: the questions the first deploy of M1 settles (RESULTS.md, "The settle answers",
# items 1 to 12; FRAMEWORK.md 6.2, "M1 also settles"), each answered from
# evidence this run saves in its own result set, audits/sfab-m1_settle_<UTC>/settle/. Run it on a
# lab that make up brought to green; `make settle` does.
#
#   1  the firewall keeps the paloalto_panos kind's default login: no ${SFAB_*} in the topology,
#      no USERNAME or PASSWORD in its env, the login on its launcher's command line (presence and
#      a keyed mark, never a value); and containerlab passes devices: on kind linux
#   2  the credentials each dell_sonic container was given, and a show version login with them
#   3  parity of every switch against the empty normalize table, with the running lines the
#      render does not account for (parity.py --reverse)
#   4  TCP between the guests with the guests' TX checksum offload on, then off again
#   5  the pair facing the firewall's ae1: LACP, PortChannel10, a tagged SYN on each ae1 member
#   6  the MCLAG keepalive in VRF mgmt on the passthrough addresses
#   7  mtu 9216 with mclag 1 on PortChannel10, and PortChannel1's MTU left alone
#   8  the forwarding-only reads on the switches that carry only VLANs
#   9  the PA-VM: who committed the startup file, rule descriptions, jumbo frames, LACP text
#  10  the vm-node guests: base disk, NIC wiring, netplan's table and rule, hostname, the relay's
#      cross-rail path at 9000 bytes, and NIC names across a guest reboot (k8s-gpu2 is rebooted)
#  11  the launcher's extra `end`: the only "% Error" each switch's typed session shows
#  12  the steps that SKIP until their part exists: the memory watchdog and node-sync
#
# Item 4 changes the guests' TX offload and puts it back; item 10 reboots k8s-gpu2 and waits for it.
# Nothing else is changed. --skip-reboot leaves k8s-gpu2 alone (item 10's reboot line is a SKIP).
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(dirname "$0")/../../common/lib.sh"
sfab_init settle "$@"

EV="$RS/settle"
mkdir -p "$EV"
REBOOT=1
for a in "${SFAB_ARGS[@]+"${SFAB_ARGS[@]}"}"; do
  case "$a" in --skip-reboot) REBOOT=0 ;; *) die "unknown argument $a" ;; esac
done
AUDIT_PY="$SFAB_COMMON/audit"

# save FILE ARGV...: run, keep stdout and stderr in FILE; the exit status is ARGV's.
save() {
  local f="$1" rc=0
  shift
  "$@" >"$f" 2>&1 || rc=$?
  return "$rc"
}
# kbody SW CMD FILE: one KLISH command's output (without its prompt line) into FILE.
kbody() { SW "$1" "$2" | klish_body "$2" >"$3"; }
# sha12: the first 12 hex digits of the sha256 of stdin.
sha12() { sha256sum | cut -c1-12; }
secret_of() { sed -n "s/^$1=//p" "$STATEDIR/secrets.env" | head -n 1; }
rel() { printf '%s' "${1#"$RS"/}"; }

# --- 1 ---------------------------------------------------------------------------------------------
settle_1() {
  local fw="$FW_NODE" f g out
  sec "1 the firewall's login and \${SFAB_*} references, and devices: on kind linux"
  # The PA-VM keeps containerlab's paloalto_panos default login, as the switches do: the topology
  # passes it no USERNAME or PASSWORD, and the kind puts the login on the
  # launcher's command line. Presence and a keyed mark only (redact.py's), never a value; nothing
  # is read from state/secrets.env for the firewall.
  f="$EV/1-fw-env.txt"
  dk inspect -f '{{json .Config}}' "$(ctr "$fw")" | py -c '
import json, sys
sys.path.insert(0, sys.argv[1])
import redact
key = redact.read_key(sys.argv[2])
cfg = json.load(sys.stdin) or {}
cmd = cfg.get("Cmd") or []
env = dict(e.split("=", 1) for e in (cfg.get("Env") or []) if "=" in e)
h = lambda s: redact.mark(s, key)
for var in ("USERNAME", "PASSWORD"):
    v = env.get(var)
    print(f"{var}: " + ("absent" if v is None else f"present, {len(v)} characters, {h(v)}"))
arg = lambda n: cmd[cmd.index(n) + 1] if n in cmd and cmd.index(n) + 1 < len(cmd) else None
u, p = arg("--username"), arg("--password")
print("launcher command line: --username " + ("absent" if u is None else u) + "; --password "
      + ("absent" if p is None else f"present, {h(p)} (the kind default)"))
' "$SFAB_COMMON/audit" "$STATEDIR/secrets/redact.key" >"$f" || true
  # shellcheck disable=SC2016 # the literal ${SFAB_ references, as the topology holds them
  grep -n '\${SFAB_' "$TOPO" >"$EV/1-topo-refs.txt" || true
  if [ -s "$EV/1-topo-refs.txt" ]; then
    bad "the topology references no \${SFAB_*}" "$(paste -sd ';' "$EV/1-topo-refs.txt")"
  else
    ok "the topology references no \${SFAB_*}, so containerlab has nothing to expand (expansion on 0.81.0 was settled before the topology stopped passing the firewall credentials on 2026-10-14: RESULTS.md, settle item 1)"
  fi
  if grep -qx 'USERNAME: absent' "$f" && grep -qx 'PASSWORD: absent' "$f"; then
    ok "$fw: no USERNAME or PASSWORD in the container env: the topology passes the PA-VM no credentials ($(rel "$f"))"
  else
    bad "$fw: no USERNAME or PASSWORD in the container env" "see $(rel "$f")"
  fi
  if grep -q '^launcher command line: --username [^;]*; --password present' "$f" && ! grep -q -- '--username absent;' "$f"; then
    ok "$fw: the launcher holds --username and --password on its command line, the paloalto_panos kind's default login the harness reads (presence and a keyed mark only: $(rel "$f"))"
  else
    bad "$fw: the launcher's login" "see $(rel "$f")"
  fi
  out="$(grep -l 'Containerlab started' "$STATEDIR"/logs/up-*.log 2>/dev/null | sort | tail -n 1 || true)"
  if [ -n "$out" ]; then
    grep -v '[│├╭╰]' "$out" >"$EV/1-deploy.log" || true
    ok "the last containerlab deploy log kept ($(rel "$EV/1-deploy.log"), from $(basename "$out"))"
  else
    skip "the containerlab deploy log" "no up log under state/logs holds a deploy"
  fi
  for g in "${GUESTS[@]}"; do
    f="$EV/1-$g-devices.txt"
    {
      echo "+ docker inspect -f '{{json .HostConfig.Devices}}' $(ctr "$g")"
      dk inspect -f '{{json .HostConfig.Devices}}' "$(ctr "$g")"
      echo "+ docker exec $(ctr "$g") ls -l /dev/kvm /dev/net/tun"
      dk exec "$(ctr "$g")" ls -l /dev/kvm /dev/net/tun
    } >"$f" 2>&1 || true
    if grep -q '^c.* /dev/kvm$' "$f" && grep -q '^c.* /dev/net/tun$' "$f" && grep -q '"PathOnHost":"/dev/kvm"' "$f"; then
      ok "$g: devices: [/dev/kvm, /dev/net/tun] accepted on kind linux, both character devices in the container ($(rel "$f"))"
    else
      bad "$g: devices: on kind linux" "see $(rel "$f")"
    fi
  done
}

# --- 2 ---------------------------------------------------------------------------------------------
settle_2() {
  local sw f gen
  sec "2 the credentials dell_sonic gets"
  gen="$(secret_of SFAB_SW_PASSWORD)"
  f="$EV/2-switch-credentials.txt"
  : >"$f"
  for sw in "${SWITCHES[@]}"; do
    dk inspect -f '{{json .Config.Cmd}}' "$(ctr "$sw")" | GEN="$gen" SW_NAME="$sw" py -c '
import json, os, sys
sys.path.insert(0, sys.argv[1])
import redact
key = redact.read_key(sys.argv[2])
cmd = json.load(sys.stdin) or []
def arg(n):
    return cmd[cmd.index(n) + 1] if n in cmd and cmd.index(n) + 1 < len(cmd) else None
u, p, name = arg("--username"), arg("--password"), os.environ["SW_NAME"]
src = "absent" if p is None else ("the generated SFAB_SW_PASSWORD" if p == os.environ["GEN"] else "not SFAB_SW_PASSWORD")
print(f"{name}: --username {u}; --password {src}" + ("" if p is None else f", {redact.mark(p, key)}"))
' "$SFAB_COMMON/audit" "$STATEDIR/secrets/redact.key" >>"$f"
  done
  printf '\nthe topology passes the switches no credentials:\n' >>"$f"
  py - "$TOPO" >>"$f" <<'PY'
import re, sys
txt = open(sys.argv[1]).read()
for m in re.finditer(r"^    ([a-z0-9-]+):\n      kind: dell_sonic\n((?:      .*\n|        .*\n)*)", txt, re.M):
    creds = [l.strip() for l in m.group(2).splitlines() if re.search(r"USERNAME|PASSWORD|SFAB_SW", l)]
    print(f"  {m.group(1)}: {', '.join(creds) if creds else 'no USERNAME, PASSWORD or SFAB_SW_ reference'}")
PY
  if grep -q 'not SFAB_SW_PASSWORD' "$f" && ! grep -q 'the generated SFAB_SW_PASSWORD' "$f"; then
    ok "every switch container got --username admin and a password that is not SFAB_SW_PASSWORD: the topology passes none, so it is containerlab's dell_sonic default ($(rel "$f"))"
  else
    bad "switch credentials" "see $(rel "$f")"
  fi
  for sw in "${SWITCHES[@]}"; do
    f="$EV/2-$sw-show-version.txt"
    if kbody "$sw" "show version" "$f" && grep -q 'Software Version' "$f"; then
      ok "$sw: show version over SSH with the container's own credentials: $(grep -m1 'Software Version' "$f" | sed 's/^ *//') ($(rel "$f"))"
    else
      bad "$sw: show version over SSH" "see $(rel "$f")"
    fi
  done
}

# --- 3 ---------------------------------------------------------------------------------------------
settle_3() {
  local sw run par rc
  sec "3 the first rows of spec/klish-normalize.yaml"
  for sw in "${SWITCHES[@]}"; do
    run="$EV/3-$sw-running-configuration.txt"
    par="$EV/3-$sw-parity"
    kbody "$sw" "show running-configuration" "$run" || true
    rc=0
    py "$SFAB_COMMON/klish/parity.py" "$RENDERDIR/bootstrap/$sw/startup-config.cfg" "$run" --switch "$sw" \
      --normalize "$RENDERDIR/gen/klish-normalize.json" --reverse --json "$par.json" >"$par.txt" 2>&1 || rc=$?
    local miss extra rendered
    read -r rendered miss extra < <(py -c '
import json, sys
d = json.load(open(sys.argv[1]))
print(d.get("rendered"), len(d.get("missing") or []), len(d.get("extra") or []))' "$par.json" 2>/dev/null || echo "? ? ?")
    if [ "$rc" -eq 0 ] && [ "$miss" = 0 ]; then
      ok "$sw: parity 0 missing of $rendered rendered lines with the empty normalize table; $extra running lines in the rendered blocks that no rendered line accounts for ($(rel "$par.txt"))"
    else
      bad "$sw: parity with the empty normalize table" "parity.py exited $rc, $miss missing ($(rel "$par.txt"))"
    fi
  done
}

# --- 4 ---------------------------------------------------------------------------------------------
# The guest-side devices whose TX checksum offload the test turns on: the bond and its members, the
# out-of-band NIC, the rail NICs, and in each relay namespace its macvlan and veth.
GUEST_TX_DEVS='eth1 eth2 bond0 eth3 rail1 rail2 rail3 rail4 rail5 rail6 rail7 rail8'
guest_tx() {  # guest_tx NODE on|off
  H "$1" "for d in $GUEST_TX_DEVS; do ethtool -K \$d tx $2 >/dev/null 2>&1 || echo \"\$d: ethtool -K tx $2 failed\"; done; for n in 1 2 3 4 5 6 7 8; do ip netns exec gpu\$n ethtool -K rail\$n tx $2 >/dev/null 2>&1; ip netns exec gpu\$n ethtool -K relay tx $2 >/dev/null 2>&1; done; for d in $GUEST_TX_DEVS; do printf '%s ' \$d; ethtool -k \$d | grep '^tx-checksumming:'; done"
}
# addr NODE PATH: an inventory address without its length
addr() { inv get "nodes.$1.$2" | sed 's:/.*::'; }
tcp_round() {  # tcp_round LABEL: three iperf3 runs from k8s-gpu1 to k8s-gpu2, each into its own file
  local label="$1" g1="${GPU_GUESTS[0]}" g2="${GPU_GUESTS[1]}" f
  for t in "bond0 $(addr "$g2" bond.address) 5201 -" "rail1 $(addr "$g2" rails.1.address) 5202 k8s-gpu1" "relay $(addr "$g2" rails.2.address) 5203 k8s-gpu1"; do
    read -r name dst port ns <<<"$t"
    f="$EV/4-tcp-$label-$name.txt"
    if [ "$ns" = - ]; then
      save "$f" H "$g1" "timeout 30 iperf3 -c $dst -p $port -t 3 --connect-timeout 3000" || true
    else
      save "$f" H "$g1" "timeout 30 ip netns exec $ns iperf3 -c $dst -p $port -t 3 --connect-timeout 3000" || true
    fi
    local rt
    # a receiver line means the run completed; the set keeps no figure (redact.py, throughput)
    rt="$(grep -E ' sender$' "$f" | tail -n 1 | awk '{print $(NF - 1)}')"
    if grep -qE ' receiver$' "$f"; then
      ok "TCP $g1 to $g2 over $name ($dst) with the guests' TX offload $label: iperf3 completed its 3 s run, ${rt:-?} retransmits ($(rel "$f"))"
    else
      bad "TCP $g1 to $g2 over $name ($dst) with the guests' TX offload $label" "no receiver line: $(tail -n 1 "$f" | cut -c1-100) ($(rel "$f"))"
    fi
  done
}
settle_4() {
  local g1="${GPU_GUESTS[0]}" g2="${GPU_GUESTS[1]}"
  sec "4 guest-side TX checksum offload"
  # servers on k8s-gpu2: the bond address, rail 1 in its namespace gpu1, rail 2 in its namespace gpu2
  H "$g2" "pkill -x iperf3 || true; iperf3 -s -D -B $(addr "$g2" bond.address) -p 5201; ip netns exec gpu1 iperf3 -s -D -B $(addr "$g2" rails.1.address) -p 5202; ip netns exec gpu2 iperf3 -s -D -B $(addr "$g2" rails.2.address) -p 5203; sleep 1; pgrep -c -x iperf3" \
    >"$EV/4-servers.txt" 2>&1 || true
  # the container side stays as vm-init.sh left it (off) throughout
  # shellcheck disable=SC2016 # expanded by the container's shell
  for g in "$g1" "$g2"; do save "$EV/4-$g-container-tx.txt" X "$g" sh -c 'for i in $(ls /sys/class/net | grep -E "^(eth[1-9][0-9]*|tap[1-9][0-9]*)$" | sort -V); do printf "%s " $i; ethtool -k $i | grep "^tx-checksumming:"; done' || true; done
  tcp_round off
  trap 'guest_tx "$g1" off >/dev/null 2>&1 || true; guest_tx "$g2" off >/dev/null 2>&1 || true' EXIT
  save "$EV/4-$g1-guest-tx-on.txt" guest_tx "$g1" on || true
  save "$EV/4-$g2-guest-tx-on.txt" guest_tx "$g2" on || true
  if grep -q 'tx-checksumming: on' "$EV/4-$g1-guest-tx-on.txt"; then
    ok "guest TX checksum offload turned on in $g1 and $g2 ($(rel "$EV/4-$g1-guest-tx-on.txt"))"
  else
    bad "guest TX checksum offload turned on" "see $(rel "$EV/4-$g1-guest-tx-on.txt")"
  fi
  tcp_round on
  save "$EV/4-$g1-guest-tx-off.txt" guest_tx "$g1" off || true
  save "$EV/4-$g2-guest-tx-off.txt" guest_tx "$g2" off || true
  trap - EXIT
  if ! grep -q 'tx-checksumming: on' "$EV/4-$g1-guest-tx-off.txt" "$EV/4-$g2-guest-tx-off.txt"; then
    ok "guest TX checksum offload off again in $g1 and $g2, as netsetup.sh leaves it ($(rel "$EV/4-$g1-guest-tx-off.txt"))"
  else
    bad "guest TX checksum offload off again" "see $(rel "$EV/4-$g1-guest-tx-off.txt")"
  fi
  H "$g2" "pkill -x iperf3 || true" >/dev/null 2>&1 || true
}

# --- 5 ---------------------------------------------------------------------------------------------
settle_5() {
  local fw="$FW_NODE" g1="${GPU_GUESTS[0]}" pid e sw f n p gw pids=()
  sec "5 the pair facing the firewall's ae1"
  f="$EV/5-fw-lacp.txt"
  FW "show lacp aggregate-ethernet all" >"$f" 2>&1 || true
  for e in ethernet1/1 ethernet1/2; do
    if grep -q "$e" "$f"; then ok "$fw: $e listed in show lacp aggregate-ethernet all ($(rel "$f"))"; else bad "$fw: $e in the LACP aggregate" "absent from $(rel "$f")"; fi
  done
  if grep -qi '02:5a:00:00:00:01' "$f"; then
    ok "$fw: the LACP partner is the pair's mclag-system-mac 02:5a:00:00:00:01 ($(rel "$f"))"
  else
    bad "$fw: LACP partner 02:5a:00:00:00:01" "not in $(rel "$f")"
  fi
  for sw in ${PAIR_MEMBERS[${PAIRS[0]}]}; do
    f="$EV/5-$sw-portchannel-summary.txt"
    kbody "$sw" "show PortChannel summary" "$f" || true
    if grep -Eq 'PortChannel10 *\(U\).*Ethernet2\(P\)' "$f"; then
      ok "$sw: PortChannel10 (U) with Ethernet2(P) ($(rel "$f"))"
    else
      bad "$sw: PortChannel10 up with Ethernet2" "see $(rel "$f")"
    fi
  done
  # a tagged SYN on each ae1 member: captures on the firewall container's eth1 and eth2 (the
  # members ethernet1/1 and ethernet1/2), while k8s-gpu1 opens TCP to the VLAN 100 gateway from 16
  # source ports, so its layer3+4 hash puts flows on both bond legs and so both pair members.
  gw="$(inv get nodes."$g1".gateway)"
  pid="$(pid_of "$fw")"
  for e in eth1 eth2; do
    nsenter -t "$pid" -n timeout 60 tcpdump -i "$e" -nn -U -s 256 -w "$EV/5-fw-$e.pcap" \
      "vlan 100 and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack = 0" >"$EV/5-fw-$e.tcpdump.txt" 2>&1 &
    pids+=("$!")
  done
  until [ -f "$EV/5-fw-eth1.pcap" ] && [ -f "$EV/5-fw-eth2.pcap" ]; do sleep 1; done
  sleep 3
  save "$EV/5-k8s-gpu1-syns.txt" H "$g1" "ping -c 2 -W 2 $gw; for p in \$(seq 40001 40016); do curl -s -o /dev/null -m 1 --local-port \$p http://$gw:443/ ; echo \"port \$p: curl exit \$?\"; done" || true
  sleep 3
  for p in "${pids[@]}"; do kill -INT "$p" 2>/dev/null || true; done
  for p in "${pids[@]}"; do wait "$p" 2>/dev/null || true; done
  for e in eth1 eth2; do
    tcpdump -r "$EV/5-fw-$e.pcap" -nn -e -tttt >"$EV/5-fw-$e.txt" 2>/dev/null || true
    n="$(grep -c 'ethertype 802.1Q (0x8100).*vlan 100' "$EV/5-fw-$e.txt" || true)"
    p="$(grep -c "> $gw\.443: Flags \[S\]" "$EV/5-fw-$e.txt" || true)"
    if [ "${n:-0}" -ge 1 ] && [ "${p:-0}" -ge 1 ]; then
      ok "$fw $e (ae1 member): $p SYNs from $g1 to $gw:443 tagged 802.1Q VLAN 100 ($(rel "$EV/5-fw-$e.txt"))"
    else
      bad "$fw $e (ae1 member): a tagged SYN" "$n tagged frames, $p SYNs to $gw:443 ($(rel "$EV/5-fw-$e.txt"))"
    fi
  done
}

# --- 6 ---------------------------------------------------------------------------------------------
settle_6() {
  local sw f src peer
  sec "6 the MCLAG keepalive in VRF mgmt under the final launcher"
  for sw in ${PAIR_MEMBERS[${PAIRS[0]}]}; do
    f="$EV/6-$sw-mclag-brief.txt"
    kbody "$sw" "show mclag brief" "$f" || true
    src="$(inv get nodes."$sw".mclag.source_ip)"
    peer="$(inv get nodes."$sw".mclag.peer_ip)"
    if grep -Eq '^ *Session Status *: *up' "$f" && grep -Eq "^ *Source Address *: *$src\$" "$f" &&
      grep -Eq "^ *Peer Address *: *$peer\$" "$f" && grep -Eq '^ *Session Vrf *: *mgmt' "$f"; then
      ok "$sw: session up, keepalive in VRF mgmt from $src to $peer ($(rel "$f"))"
    else
      bad "$sw: keepalive" "see $(rel "$f")"
    fi
  done
}

# --- 7 ---------------------------------------------------------------------------------------------
settle_7() {
  local sw run
  sec "7 mtu 9216 with mclag 1 on PortChannel10"
  for sw in ${PAIR_MEMBERS[${PAIRS[0]}]}; do
    run="$EV/3-$sw-running-configuration.txt"
    py - "$run" "$sw" >"$EV/7-$sw-mtu.txt" <<'PY'
import re, sys
sys.path.insert(0, __import__("os").environ["AUDIT_PY"])
import judge
blocks = {}
for h, body in judge.p_blocks(open(sys.argv[1]).read()):
    blocks.setdefault(re.sub(r"\s+", "", h), []).extend(body)
for name in ("interfacePortChannel10", "interfaceEthernet2", "interfacePortChannel1", "interfaceEthernet0", "interfaceEthernet1"):
    body = blocks.get(name)
    mtu = [l for l in (body or []) if l.startswith("mtu")]
    print(f"{name}: {'absent' if body is None else (mtu[0] if mtu else 'no mtu line')}" + (f"; {', '.join(l for l in body if l.startswith(('mclag', 'switchport')))}" if body else ""))
PY
    if grep -q '^interfacePortChannel10: mtu 9216; .*mclag 1' "$EV/7-$sw-mtu.txt" && grep -q '^interfaceEthernet2: mtu 9216' "$EV/7-$sw-mtu.txt"; then
      ok "$sw: KLISH kept mtu 9216 on PortChannel10 beside mclag 1 and the trunk, and on its member Ethernet2 ($(rel "$EV/7-$sw-mtu.txt"))"
    else
      bad "$sw: mtu 9216 on PortChannel10 and Ethernet2" "see $(rel "$EV/7-$sw-mtu.txt")"
    fi
    if grep -q '^interfacePortChannel1: no mtu line' "$EV/7-$sw-mtu.txt"; then
      ok "$sw: the switch added no mtu line to PortChannel1 (the peer link stays at the default)"
    else
      bad "$sw: PortChannel1 MTU left alone" "$(grep '^interfacePortChannel1:' "$EV/7-$sw-mtu.txt")"
    fi
  done
}

# --- 8 ---------------------------------------------------------------------------------------------
settle_8() {
  local sw a b
  sec "8 ip vrf mgmt on the switches that carry only VLANs"
  for sw in "${SWITCHES[@]}"; do
    [[ " ${PAIR_MEMBERS[*]} " != *" $sw "* ]] || continue
    a="$EV/8-$sw-show-ip-interfaces.txt"
    b="$EV/8-$sw-show-ip-route.txt"
    kbody "$sw" "show ip interfaces" "$a" || true
    kbody "$sw" "show ip route" "$b" || true
    local ifs
    ifs="$(py -c '
import os, sys
sys.path.insert(0, os.environ["AUDIT_PY"])
import judge
print(",".join(r["iface"] + ":" + (r["vrf"] or "default") for r in judge.p_ip_interfaces(open(sys.argv[1]).read())))' "$a")"
    if [ "$ifs" = "Management0:mgmt" ] && [ -z "$(tr -d '[:space:]' <"$b")" ]; then
      ok "$sw: show ip interfaces lists only Management0, in VRF mgmt; show ip route prints nothing ($(rel "$a"), $(rel "$b"))"
    else
      bad "$sw: forwarding-only reads" "interfaces ${ifs:-none}; show ip route $(grep -c . "$b" || true) lines"
    fi
  done
}

# --- 9 ---------------------------------------------------------------------------------------------
settle_9() {
  local fw="$FW_NODE" c f
  c="$(ctr "$fw")"
  sec "9 the PA-VM's startup steps"
  f="$EV/9-fw-launcher.txt"
  dk logs "$c" 2>&1 | sed $'s/\x1b\\[[0-9;?]*[A-Za-z]//g' |
    grep -aE 'launch +(INFO|WARNING|ERROR)|XML startup config|startup-config|jumbo|Startup complete' |
    grep -avE 'password|PASSWORD|Environment variables' >"$f" || true
  if grep -q 'XML startup config commit finished: result=OK' "$f"; then
    ok "$fw: the image's launcher committed the startup file itself (its log line is in $(rel "$f")); fw-startup.py was not needed"
  elif dk exec "$c" test -f /tmp/lab-startup-committed; then
    ok "$fw: the launcher did not log a commit; fw-startup.py committed the file and left /tmp/lab-startup-committed ($(rel "$f"))"
  else
    bad "$fw: startup file committed" "neither the launcher's line nor the marker ($(rel "$f"))"
  fi
  grep -h 'fw-startup\|commit' "$STATEDIR"/logs/boot-*.log >"$EV/9-boot-fw-lines.txt" 2>/dev/null || true
  f="$EV/9-fw-config-set.txt"
  FW "set cli config-output-format set" "configure" "show" "exit" >"$f" 2>&1 || true
  # every <description> the render gives a security rule, as a set-format line in the running config
  local res
  res="$(py - "$RENDERDIR/bootstrap/$fw/startup-config.xml" "$f" <<'PY'
import sys
import xml.etree.ElementTree as ET
want = []
for rule in ET.parse(sys.argv[1]).getroot().iter("entry"):
    d = rule.find("description")
    if d is not None and rule.find("action") is not None and d.text:
        want.append(f"set rulebase security rules {rule.get('name')} description {d.text.strip()}")
have = {" ".join(l.split()) for l in open(sys.argv[2], encoding="utf-8", errors="replace")}
miss = [w for w in want if w not in have]
print(len(want), len(miss), "; ".join(miss[:2]))
PY
)"
  local nw nm
  read -r nw nm _ <<<"$res"
  if [ "${nw:-0}" -gt 0 ] && [ "$nm" = 0 ]; then
    ok "$fw: all $nw rule descriptions the render sets are in the running configuration ($(rel "$f"))"
  else
    bad "$fw: rule descriptions" "$res ($(rel "$f"))"
  fi
  FW "show system setting jumbo-frame" >"$EV/9-fw-jumbo-cli.txt" 2>&1 || true
  FWX "<show><system><setting><jumbo-frame/></setting></system></show>" >"$EV/9-fw-jumbo-xml.xml" 2>&1 || true
  if grep -qi 'on' "$EV/9-fw-jumbo-cli.txt" && grep -q 'status="success"' "$EV/9-fw-jumbo-xml.xml"; then
    ok "$fw: jumbo frames: the CLI says $(grep -io 'jumbo[^<]*' "$EV/9-fw-jumbo-cli.txt" | tail -n 1 | tr -s ' '), the XML API answers $(sed -n 's:.*<result>\(.*\)</result>.*:\1:p' "$EV/9-fw-jumbo-xml.xml" | head -c 80) ($(rel "$EV/9-fw-jumbo-xml.xml"))"
  else
    bad "$fw: jumbo-frame status" "see $(rel "$EV/9-fw-jumbo-cli.txt") and $(rel "$EV/9-fw-jumbo-xml.xml")"
  fi
  FW "show interface ae1.100" >"$EV/9-fw-show-interface-ae1.100.txt" 2>&1 || true
  ok "$fw: the text the audit parses kept: $(rel "$EV/5-fw-lacp.txt") and $(rel "$EV/9-fw-show-interface-ae1.100.txt")"
}

# --- 10 --------------------------------------------------------------------------------------------
boot_id() { EVID_OFF=1 H "$1" "cat /proc/sys/kernel/random/boot_id" 2>/dev/null || true; }
settle_10() {
  local g f img base before after b0 b1 deadline
  sec "10 the vm-node image, end to end"
  img="$(dk image inspect -f '{{.Id}}' "${NODE_IMAGE[${GUESTS[0]}]}" 2>/dev/null || echo absent)"
  for g in "${GUESTS[@]}"; do
    base="$(head -n 1 "$STATEDIR/nodes/$g/base.id" 2>/dev/null || echo none)"
    ok "$g: root disk an overlay of the baked base $base, image ${NODE_IMAGE[$g]} (${img:7:12})"
    f="$EV/10-$g-wiring.txt"
    dk logs "$(ctr "$g")" 2>&1 | grep -E '^\[vm-init\]' >"$f" || true
    if grep -q 'wired eth0 (bridge) and the data NICs:' "$f"; then
      if grep 'wired eth0' "$f" | tail -n 1 | grep -q ':tc'; then
        ok "$g: the host kernel refused group_fwd_mask 0x4004, so some data NICs use the tc redirect ($(rel "$f"))"
      else
        ok "$g: every data NIC bridged with group_fwd_mask 0x4004 (the host kernel took it; no tc fallback) ($(rel "$f"))"
      fi
    else
      bad "$g: NIC wiring" "no wired line in $(rel "$f")"
    fi
    f="$EV/10-$g-netplan.txt"
    save "$f" H "$g" "hostnamectl --static; echo; cloud-init status --long | grep -E '^(status|boot_status_code|detail)' ; echo; ip rule show; echo; ip route show table main; echo; ip route show table 100; echo; cat /etc/netplan/50-cloud-init.yaml" || true
    save "$EV/10-$g-table-150.txt" H "$g" "ip route show table 150" || true
    local mg
    mg="$(node_mgmt "$g")"
    if grep -q "^[0-9]*:.*from $mg lookup 150" "$f" && grep -q "^default via $(inv get mgmt.gw) dev eth0" "$EV/10-$g-table-150.txt" &&
      [ "$(head -n 1 "$f")" = "$g" ]; then
      ok "$g: hostname $g; netplan's rule from $mg lookup 150 and the management default in table 150 on first boot ($(rel "$f"))"
    else
      bad "$g: netplan table, rule and hostname" "see $(rel "$f")"
    fi
  done
  local g1="${GPU_GUESTS[0]}" g2="${GPU_GUESTS[1]}" r nr dst
  for r in 1 2 3 4 5 6 7 8; do
    nr=$((r % 8 + 1))
    dst="$(addr "$g2" "rails.$nr.address")"
    f="$EV/10-relay-rail$r-to-rail$nr-9000.txt"
    save "$f" H "$g1" "ip netns exec gpu$r ping -c 3 -W 2 -M do -s 8972 $dst" || true
    if grep -Eq '[1-9][0-9]* (packets )?received' "$f" && ! grep -qi 'message too long' "$f"; then
      ok "rail $r to rail $nr through the relay: 9000-byte DF ping $g1 ns gpu$r to $g2 ($dst) $(grep -Eo '[0-9]+ packets transmitted, [0-9]+ received' "$f") ($(rel "$f"))"
    else
      bad "rail $r to rail $nr through the relay at 9000 bytes" "see $(rel "$f")"
    fi
  done
  if [ "$REBOOT" != 1 ]; then
    skip "NIC names across a guest reboot" "--skip-reboot"
    return 0
  fi
  before="$EV/10-$g2-links-before-reboot.txt"
  after="$EV/10-$g2-links-after-reboot.txt"
  save "$before" H "$g2" "ip -br link | grep -vE '^(lo|relay|veth|sfmv|rl[0-9])' | awk '{print \$1, \$3}' | sed 's/@[^ ]*//' | sort" || true
  b0="$(boot_id "$g2")"
  H "$g2" "systemctl reboot" >/dev/null 2>&1 || true
  deadline=$((SECONDS + 600))
  b1="$b0"
  while [ $SECONDS -lt $deadline ]; do
    sleep 10
    b1="$(boot_id "$g2")"
    [ -n "$b1" ] && [ "$b1" != "$b0" ] && break
  done
  if [ -z "$b1" ] || [ "$b1" = "$b0" ]; then
    bad "$g2: back after a reboot" "no new boot within 600 s"
    return 0
  fi
  deadline=$((SECONDS + 300))
  until EVID_OFF=1 H "$g2" "systemctl show -p Result --value sfab-netsetup.service" 2>/dev/null | grep -qx success; do
    [ $SECONDS -lt $deadline ] || break
    sleep 5
  done
  save "$after" H "$g2" "ip -br link | grep -vE '^(lo|relay|veth|sfmv|rl[0-9])' | awk '{print \$1, \$3}' | sed 's/@[^ ]*//' | sort" || true
  save "$EV/10-$g2-netsetup-after-reboot.txt" H "$g2" "journalctl -b -u sfab-netsetup.service --no-pager -o cat" || true
  if [ -s "$before" ] && cmp -s "$before" "$after" && ! grep -q 'renamed' "$EV/10-$g2-netsetup-after-reboot.txt"; then
    ok "$g2: after a guest reboot every NIC has the same name and MAC, named by the .link files (netsetup renamed none) ($(rel "$after"))"
  else
    bad "$g2: NIC names across a reboot" "see $(rel "$before"), $(rel "$after") and $(rel "$EV/10-$g2-netsetup-after-reboot.txt")"
  fi
}

# --- 11 --------------------------------------------------------------------------------------------
settle_11() {
  local sw f total other
  sec "11 the launcher's extra end"
  for sw in "${SWITCHES[@]}"; do
    f="$EV/11-$sw-typed-session.txt"
    dk logs "$(ctr "$sw")" 2>&1 | sed $'s/\x1b\\[[0-9;?]*[A-Za-z]//g' | tr -d '\r' |
      sed -n '/typing KLISH startup config/,/KLISH startup config applied/p' >"$f" || true
    # the launcher's log shows each read twice (the console stream and its own echo of it);
    # every "% Error" must sit two lines below a line that ends with the typed "end"
    read -r total other < <(awk '/% Error/ {t++; if (p2 !~ /end$/) o++} {p2 = p1; p1 = $0} END {print t + 0, o + 0}' "$f")
    if [ "$total" -gt 0 ] && [ "$other" = 0 ] && [ "$(grep -v '^!' "$RENDERDIR/bootstrap/$sw/startup-config.cfg" | grep -v '^$' | tail -n 1)" = end ]; then
      ok "$sw: the only error in the typed session is \"% Error: Invalid input detected\" after the launcher's own end (the file already ended with end; the log shows it $total times, once per echo) ($(rel "$f"))"
    elif [ "$total" = 0 ]; then
      ok "$sw: no \"% Error\" in the typed session ($(rel "$f"))"
    else
      bad "$sw: typed session errors" "$other of $total error lines follow something other than end ($(rel "$f"))"
    fi
  done
}

# --- 12 --------------------------------------------------------------------------------------------
settle_12() {
  local f last
  sec "12 the steps that SKIP until their part exists"
  f="$EV/12-stage-lines.txt"
  grep -h 'mem-watchdog\|memwatch\|node-sync\|node sync' "$STATEDIR"/logs/up-*.log "$STATEDIR"/logs/boot-*.log 2>/dev/null | sort | uniq -c >"$f" || true
  if grep -q 'mem-watchdog.sh is not present' "$f"; then
    ok "up ran without the memory watchdog: common/host/mem-watchdog.sh is not present ($(rel "$f"))"
  else
    bad "up without the memory watchdog" "no such line in the up logs ($(rel "$f"))"
  fi
  if grep -q 'SKIP  node-sync (common/host/node-sync.sh is not present)' "$f"; then
    ok "boot's node-sync step printed SKIP: common/host/node-sync.sh is not present ($(rel "$f"))"
  else
    bad "boot's node-sync SKIP" "no such line in the boot logs ($(rel "$f"))"
  fi
  last="$(find "$RENDERDIR/audits" -mindepth 1 -maxdepth 1 -type d -name "${LAB}_audit_*" 2>/dev/null | sort | tail -n 1)"
  if [ -n "$last" ] && [ -f "$last/verdict.txt" ]; then
    if grep -q '^  SKIP  ' "$last/verdict.txt"; then
      bad "the latest audit has no SKIP line" "$(basename "$last"): $(grep -c '^  SKIP  ' "$last/verdict.txt") SKIP lines"
    else
      ok "the latest audit, $(basename "$last"), has no SKIP line: neither step leaves one there"
    fi
  else
    skip "the latest audit has no SKIP line" "no audit result set yet"
  fi
}

export AUDIT_PY
settle_1
settle_2
settle_3
settle_5
settle_6
settle_7
settle_8
settle_9
settle_11
settle_12
settle_4
settle_10
summary
