# common/sonic/dbs.sh: one PortChannel member followed through SONiC's databases (book Chapter 3,
# "SONiC Architecture and Its Databases"), sourced by a lab's dbs.sh after sfab_init.
#
# On one switch (DBS_SWITCH, default the pair's first member) and one server PortChannel (DBS_PC,
# default the one toward DBS_PEER, k8s-gpu1), with its member port on that switch and its access VLAN:
# the switch's containers and the SWSS and teamd processes, the KLISH running configuration, then
# the keys and fields in CONFIG_DB, APPL_DB, STATE_DB, COUNTERS_DB and ASIC_DB. Each read is saved
# as <db>/<n>-<what>.txt in the shell form a reader types (prompt line, then output), and the
# checks tie them together: the CONFIG_DB entries have APPL_DB and STATE_DB counterparts, and in
# ASIC_DB a chain of SAI objects leads from the port object COUNTERS_DB names for the member, to
# its LAG member, the LAG, the LAG's bridge port, and the VLAN member that puts that bridge port
# untagged in the access VLAN. Read-only: nothing is written to any database or device.

DBS_PEER="${DBS_PEER:-k8s-gpu1}"

# dbs_pick: DBS_SWITCH, DBS_PC, DBS_MEMBER and DBS_VLAN from the inventory
dbs_pick() {
  local out
  out="$(py - "$INV" "${DBS_SWITCH:-}" "$DBS_PEER" "${DBS_PC:-}" <<'PY'
import json, sys
inv, sw, peer, pc = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
nodes = json.load(open(inv))["nodes"]
if not sw:
    sw = sorted(n for n, v in nodes.items() if v.get("role") == "mclag_member")[0]
pcs = nodes[sw]["portchannels"]
if not pc:
    pc = [p for p, v in pcs.items() if v.get("peer_node") == peer][0]
v = pcs[pc]
print(sw, pc, v["members"][0], v["vlans"][0])
PY
)" || return 1
  read -r DBS_SWITCH DBS_PC DBS_MEMBER DBS_VLAN <<<"$out"
}

# dbs_read DIR NAME CMD: run CMD in the switch's shell, save prompt line and output as DIR/NAME.txt
dbs_read() {
  local dir="$1" name="$2" cmd="$3" f
  mkdir -p "$RS/$dir"
  f="$RS/$dir/$name.txt"
  { printf '%s@%s:~$ %s\n' "$CRED_USER" "$DBS_SWITCH" "$cmd"; SH "$DBS_SWITCH" "$cmd" 2>&1 || true; } >"$f"
  tail -n +2 "$f"
}

# dbs_has FILE TEXT LABEL: PASS when the saved output (not its prompt line) holds TEXT
dbs_has() {
  if tail -n +2 "$RS/$1.txt" | grep -qF -- "$2"; then ok "$3"; else bad "$3" "$2 not in $1.txt"; fi
}

# dbs_field FILE FIELD: a field's value from a saved hgetall, which SONiC 4.6.0's sonic-db-cli
# prints as alternating field and value lines
dbs_field() {
  tail -n +2 "$RS/$1.txt" | grep -v '^ASIC_STATE:' | awk -v f="$2" 'NR % 2 == 1 && $0 == f { getline v; print v; exit }' || true
}

# dbs_is FILE FIELD WANT LABEL: PASS when the field holds WANT
dbs_is() {
  local v
  v="$(dbs_field "$1" "$2")"
  if [ "$v" = "$3" ]; then ok "$4"; else bad "$4" "$2 is '${v}' in $1.txt"; fi
}

# dbs_find DIR NAME TYPE FIELD VALUE [FIELD2 VALUE2]: the ASIC_DB objects of TYPE whose FIELD is
# VALUE (and FIELD2 VALUE2), each key then its fields, saved as DIR/NAME.txt; prints the first key
# found. A bridge port in more than one VLAN has a VLAN member for each, so the VLAN member is found
# by its bridge port and its VLAN both.
dbs_find() {
  local also=""
  [ -n "${6:-}" ] && also=" && [ \"\$(sonic-db-cli ASIC_DB hget \"\$k\" $6)\" = '$7' ]"
  dbs_read "$1" "$2" "for k in \$(sonic-db-cli ASIC_DB keys 'ASIC_STATE:$3:*'); do [ \"\$(sonic-db-cli ASIC_DB hget \"\$k\" $4)\" = '$5' ]$also && echo \"\$k\" && sonic-db-cli ASIC_DB hgetall \"\$k\"; done" >/dev/null
  tail -n +2 "$RS/$1/$2.txt" | grep -m 1 "^ASIC_STATE:$3:" | sed "s/^ASIC_STATE:$3://" || true
}

dbs_run() {
  local sw pc m vl vid port_oid lag_oid lm bp vlan_oid vm c p
  dbs_pick || { bad "dbs: pick the PortChannel" "cannot read $INV"; summary; return; }
  _creds "$DBS_SWITCH" || { bad "dbs: credentials for $DBS_SWITCH" "none"; summary; return; }
  sw="$DBS_SWITCH" pc="$DBS_PC" m="$DBS_MEMBER" vid="$DBS_VLAN" vl="Vlan$DBS_VLAN"
  printf 'switch: %s\nportchannel: %s\nmember: %s\nvlan: %s\npeer: %s\n' "$sw" "$pc" "$m" "$vl" "$DBS_PEER" >"$RS/FOLLOWED.txt"
  sec "$sw: $pc ($m, access $vl, toward $DBS_PEER) through the databases"

  sec "containers and processes"
  dbs_read proc 1-containers "docker ps --format '{{.Names}}' | sort" >/dev/null
  for c in database swss syncd teamd; do dbs_has proc/1-containers "$c" "$sw: container $c running"; done
  dbs_read proc 2-swss "docker exec swss ps -eo comm= | sort -u" >/dev/null
  for p in orchagent portmgrd vlanmgrd portsyncd; do dbs_has proc/2-swss "$p" "$sw: $p runs in swss"; done
  dbs_read proc 3-teamd "docker exec teamd ps -eo comm= | sort -u" >/dev/null
  for p in teamd teammgrd teamsyncd; do dbs_has proc/3-teamd "$p" "$sw: $p runs in teamd"; done

  sec "the KLISH configuration"
  mkdir -p "$RS/klish"
  SW "$sw" "show running-configuration interface $pc" "show running-configuration interface $m" >"$RS/klish/1-running-$pc.txt" 2>&1 || true
  dbs_has klish/1-running-$pc "mclag" "$sw: KLISH shows $pc in the MCLAG domain"

  sec "CONFIG_DB"
  dbs_read config 1-keys "sonic-db-cli CONFIG_DB keys '*$pc*' | sort" >/dev/null
  dbs_has config/1-keys "PORTCHANNEL|$pc" "CONFIG_DB: PORTCHANNEL|$pc"
  dbs_has config/1-keys "PORTCHANNEL_MEMBER|$pc|$m" "CONFIG_DB: PORTCHANNEL_MEMBER|$pc|$m"
  dbs_has config/1-keys "VLAN_MEMBER|$vl|$pc" "CONFIG_DB: VLAN_MEMBER|$vl|$pc"
  dbs_read config 2-portchannel "sonic-db-cli CONFIG_DB hgetall 'PORTCHANNEL|$pc'" >/dev/null
  dbs_read config 3-vlan-member "sonic-db-cli CONFIG_DB hgetall 'VLAN_MEMBER|$vl|$pc'" >/dev/null
  dbs_is config/3-vlan-member tagging_mode untagged "CONFIG_DB: $pc is an untagged member of $vl"

  sec "APPL_DB"
  dbs_read appl 1-keys "sonic-db-cli APPL_DB keys '*$pc*' | sort" >/dev/null
  dbs_has appl/1-keys "LAG_TABLE:$pc" "APPL_DB: LAG_TABLE:$pc"
  dbs_has appl/1-keys "LAG_MEMBER_TABLE:$pc:$m" "APPL_DB: LAG_MEMBER_TABLE:$pc:$m"
  dbs_has appl/1-keys "VLAN_MEMBER_TABLE:$vl:$pc" "APPL_DB: VLAN_MEMBER_TABLE:$vl:$pc"
  dbs_read appl 2-lag "sonic-db-cli APPL_DB hgetall 'LAG_TABLE:$pc'" >/dev/null
  dbs_is appl/2-lag oper_status up "APPL_DB: $pc oper_status up"
  dbs_read appl 3-lag-member "sonic-db-cli APPL_DB hgetall 'LAG_MEMBER_TABLE:$pc:$m'" >/dev/null
  dbs_is appl/3-lag-member status enabled "APPL_DB: $m enabled in $pc"

  sec "STATE_DB"
  dbs_read state 1-keys "sonic-db-cli STATE_DB keys '*$pc*' | sort" >/dev/null
  dbs_has state/1-keys "LAG_TABLE|$pc" "STATE_DB: LAG_TABLE|$pc"
  dbs_has state/1-keys "LAG_MEMBER_TABLE|$pc|$m" "STATE_DB: LAG_MEMBER_TABLE|$pc|$m"
  dbs_read state 2-lag "sonic-db-cli STATE_DB hgetall 'LAG_TABLE|$pc'" >/dev/null
  dbs_read state 3-port "sonic-db-cli STATE_DB hgetall 'PORT_TABLE|$m'" >/dev/null
  dbs_is state/3-port netdev_oper_status up "STATE_DB: $m netdev_oper_status up"

  sec "COUNTERS_DB and ASIC_DB: port, LAG member, LAG, bridge port, VLAN member, VLAN"
  dbs_read counters 1-name-maps "sonic-db-cli COUNTERS_DB keys '*NAME_MAP*' | sort" >/dev/null
  dbs_read counters 2-port-oid "sonic-db-cli COUNTERS_DB hget COUNTERS_PORT_NAME_MAP $m" >/dev/null
  port_oid="$(tail -n +2 "$RS/counters/2-port-oid.txt" | grep -o 'oid:0x[0-9a-f]*' | head -n 1 || true)"
  if [ -n "$port_oid" ]; then ok "COUNTERS_DB: $m is $port_oid"; else bad "COUNTERS_DB: $m has an object id" "none"; summary; return; fi
  dbs_read counters 3-port-counters "sonic-db-cli COUNTERS_DB hgetall 'COUNTERS:$port_oid' | paste - - | grep -E '^(SAI_PORT_STAT_IF_IN_UCAST_PKTS|SAI_PORT_STAT_IF_OUT_UCAST_PKTS|SAI_PORT_STAT_IF_IN_ERRORS)\b'" >/dev/null
  dbs_read asic 1-port "sonic-db-cli ASIC_DB hgetall 'ASIC_STATE:SAI_OBJECT_TYPE_PORT:$port_oid'" >/dev/null
  dbs_has asic/1-port "SAI_PORT_ATTR" "ASIC_DB: the port object $port_oid exists"
  lm="$(dbs_find asic 2-lag-member SAI_OBJECT_TYPE_LAG_MEMBER SAI_LAG_MEMBER_ATTR_PORT_ID "$port_oid")"
  if [ -n "$lm" ]; then ok "ASIC_DB: LAG member $lm holds $m's port"; else bad "ASIC_DB: a LAG member holds $m's port" "none"; summary; return; fi
  lag_oid="$(dbs_field asic/2-lag-member SAI_LAG_MEMBER_ATTR_LAG_ID)"
  dbs_read asic 3-lag "sonic-db-cli ASIC_DB hgetall 'ASIC_STATE:SAI_OBJECT_TYPE_LAG:$lag_oid'" >/dev/null
  if [ -n "$lag_oid" ] && [ "$(wc -l <"$RS/asic/3-lag.txt")" -gt 1 ]; then ok "ASIC_DB: its LAG $lag_oid exists"; else bad "ASIC_DB: the member's LAG exists" "${lag_oid:-none}"; fi
  dbs_read asic 4-lag-members "for k in \$(sonic-db-cli ASIC_DB keys 'ASIC_STATE:SAI_OBJECT_TYPE_LAG_MEMBER:*'); do sonic-db-cli ASIC_DB hget \"\$k\" SAI_LAG_MEMBER_ATTR_LAG_ID; done | grep -c '$lag_oid'" >/dev/null
  dbs_is_count() { local n; n="$(tail -n +2 "$RS/asic/4-lag-members.txt" | tr -dc 0-9)"; if [ "$n" = 1 ]; then ok "ASIC_DB: $lag_oid has one member on $sw, as $pc has in CONFIG_DB"; else bad "ASIC_DB: $lag_oid has one member on $sw" "${n:-?} members"; fi; }
  dbs_is_count
  bp="$(dbs_find asic 5-bridge-port SAI_OBJECT_TYPE_BRIDGE_PORT SAI_BRIDGE_PORT_ATTR_PORT_ID "$lag_oid")"
  if [ -n "$bp" ]; then ok "ASIC_DB: bridge port $bp stands for the LAG"; else bad "ASIC_DB: a bridge port for the LAG" "none"; summary; return; fi
  vlan_oid="$(dbs_find asic 6-vlan SAI_OBJECT_TYPE_VLAN SAI_VLAN_ATTR_VLAN_ID "$vid")"
  if [ -n "$vlan_oid" ]; then ok "ASIC_DB: VLAN $vid is $vlan_oid"; else bad "ASIC_DB: a VLAN object for VLAN $vid" "none"; summary; return; fi
  vm="$(dbs_find asic 7-vlan-member SAI_OBJECT_TYPE_VLAN_MEMBER SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID "$bp" SAI_VLAN_MEMBER_ATTR_VLAN_ID "$vlan_oid")"
  if [ -n "$vm" ]; then ok "ASIC_DB: VLAN member $vm holds the bridge port in VLAN $vid"; else bad "ASIC_DB: a VLAN member holds the bridge port in VLAN $vid" "none"; fi
  dbs_is asic/7-vlan-member SAI_VLAN_MEMBER_ATTR_VLAN_ID "$vlan_oid" "ASIC_DB: that member is in VLAN $vid ($vlan_oid)"
  dbs_is asic/7-vlan-member SAI_VLAN_MEMBER_ATTR_VLAN_TAGGING_MODE SAI_VLAN_TAGGING_MODE_UNTAGGED "ASIC_DB: untagged, as CONFIG_DB says"
  summary
}
