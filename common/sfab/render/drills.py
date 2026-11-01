"""gen/drills.json and gen/breaks.json: a chapter's drills (chapter.yaml drills:) and its breaks
(breaks/<id>.yaml), resolved against the lab's inventory (FRAMEWORK.md sections 4.6 and 4.7).

Both are rendered, as spec/klish-normalize.yaml becomes gen/klish-normalize.json, so the scripts
that run them (common/drill/, common/breakheal.py) need no PyYAML on the lab host, and `sfab
check` reports a changed drill or break as drift. A lab with no drills block renders no
gen/drills.json, and a lab with no breaks/ directory no gen/breaks.json.

The drills block, as chapter.yaml holds it:

    drills:
      probes:
        ping:   {from: k8s-gpu1, to: k8s-gpu2, count: 8, id_base: 3100, interval_s: 0.1}
        tcp:    {from: ent-client, gateway: gw-users, port: 443, interval_s: 0.1, timeout_s: 1}
        orphan: {from: bastion, to: truenas1, address: mgmt_if, port: 443, interval_s: 0.2, timeout_s: 1}
      timing: {lead_s: 10, place_s: 4, place_tries: 5, hold_s: 30, tail_s: 20, ...}
      list:
        - {id: fw-leg, title: ..., shut: {switch: fe-sw1, portchannel: 10}, probes: [ping, tcp],
           place: {tcp: target}, peer_link_counters: true}
        - {id: standby-reboot, title: ..., reboot: standby, probes: [ping, tcp], place: {ping: target}}

A shut names a switch and one of its PortChannels, its dedicated keepalive link (keepalive: true),
or both; the render resolves the ports on that switch (native names and container ports) and the
KLISH the drill types: one port as `interface EthernetN`, contiguous ports as `interface range
EthernetA-B`, each followed by shutdown (restore: no shutdown). A shut drill may hold its own hold_s
(a keepalive cut must outlast the session timeout) and await_return: true, which runs the monitor
through the drill and, after the restore, waits up to return_max_s for every bond to be back on
two legs (the standby holds its MCLAG ports down for delay-restore after the keepalive returns). A
reboot names a role, read from show mclag brief when the drill runs. place says what the drill must see before it cuts, per probe: target (at least one probe
instance crosses the switch the fault is on, and at least one does not) or both (instances leave
the source on both of its legs). Every KLISH line passes sfab.klish_lint.action_problems.

A break file, breaks/<id>.yaml:

    title: one line
    exercise: the chapter's exercise number (metadata)
    break:  [{klish: {node, context, lines, fallback}}]       typed in one session each
    record: [{show: {node, lines}}, {probe_tcp: {from, to, address, port, count, interval_s, timeout_s, passes}}]
    expect_broken: [{vlan_member: {node, vlan, port, present, mode}}, {probe_share: {probe, failing: some}}]
    heal:   [{restore: <switch>}]
    expect_healed: [{vlan_member: ...}, {parity: {node}}, {probe_share: {probe, failing: none}}]

The klish action's fallback is one alternative line list, typed only when the switch answers the
first with "% Error"; the line it took is recorded, and the break file is then fixed to it
(FRAMEWORK.md 4.7: the exact lines are fixed when the break is first run).

Chapter 4 adds the firewall. Its drills change the firewall live through the XML API and put the
render back after, each restore pushed before the change:

    drills:
      probes:
        public: {from: k8s-cp2, to: public, count: 5, interval_s: 0.5, timeout_s: 1}
      timing: {settle_s: 5, ntp_wait_s: 300, log_pause_s: 10}
      list:
        - {id: land, title: ..., nat_removed: no-nat-public, counter: flow_policy_nat_land, probe: public,
           capture: [receive, drop]}
        - {id: ntp-uplink, title: ..., service_route: {service: ntp, interface: ethernet1/5, with: [dns]},
           expect_rule: deny-all-log}

The public probe pings an address from a node (a VM guest, or a container with ping): the firewall's
public address (to: public), a node (its primary address), or an address. nat_removed names a NAT
rule the render carries; the plan holds its xpath, its rendered entry (sfab.render.panos.nat_rule)
and where it goes back (before the rule that follows it in the render), the counter the drill reads
around the probe in show counter global, the packet-diag filter (the probe's source and
destination) and stages, and the container ports captured on the lab host (the bundle's members
and the public interface). service_route names one of the firewall's own services and the
interface its route is moved to: the plan holds the service route's xpath, the entry that moves it
and the rendered entry that puts it back, the server, the rule that admits the service from its
rendered interface (read after the restore) and the rule expected to drop it from the new one.
with: lists the other services whose server is the same address, which move with it: on the PA-VM
12.1.2 the firewall's NTP to the bastion kept the source of the DNS service route, whose server is
the same address, when only the NTP route moved (ch04/RESULTS.md, problem 5), so a service sharing the
server must be listed, and the plan holds each one's route the same way, its port, the rule that
admits it and the domain a lookup through it is made in.

A break may now act on the firewall: panos_api {del: nat|security, rule} and panos_api {set:
nat|security, rule} (the rendered entry, put back where the render places it; one commit after the
part's firewall actions), fw_show {lines} (CLI reads, saved), probe_ping {id, from, to, count,
interval_s, timeout_s, passes, counters} (the counters are read in show counter global before and
after each pass), probe_http {id, from, hostname, path, count, interval_s, timeout_s, passes} (curl
from a client, through its own resolver), and the checks counter {name, probe, rise}, rule_order
{} (the running rulebase in the render's order) and probe_share {failing: all}.

Chapter 5 adds the rails. Its drill darkens a whole rail switch:

    drills:
      probes:
        rails: {from: k8s-gpu1, to: k8s-gpu2, id_base: 5500, interval_s: 0.2, cross: [[2, 1], [1, 2], [2, 4]]}
      timing: {lead_s: 10, hold_s: 30, tail_s: 20, whole_polls: 12}
      list:
        - {id: dark-switch, title: ..., dark: {switch: rail-sw1}, probes: [rails]}

The rails probe pings from the from node's GPU namespaces: one row per rail both nodes hold (to the
to node's address on that rail) and one per cross pair [a, b] (from rail a's namespace to the to
node's address on rail b, so the request rides rail b and the reply, through the to node's relay,
rail a), each row under its own ICMP id; its captures are both nodes' container ports on every
rail. dark names a rail switch: the plan holds every port it uses (as one interface range when the
ports are contiguous), the KLISH that shuts them all and the KLISH that gives them no shutdown, its
rails (dead while it is shut) and the other rails, and each row's expectation while it is dark: a
row whose request or reply rides a dead rail is dark, every other row answers.

A break may now act on a VM guest's relay: relay_route {node, rail, to_rail, src: none|rendered}
(the relay route from namespace gpu<rail> to rail to_rail replaced without its source pin, or with
the rendered one), ns_show {node, rail, to, get} (the namespace's route table, and route get for
the to node's address on each rail of get), probe_rail {id, from, to, rail, to_rail, count,
interval_s, timeout_s, passes, capture} (pings from namespace gpu<rail> on from to the to node's
address on to_rail, or on every rail with rail: all; capture: true records the far node's rail NIC
and relay bridge in the guest around each pass), and the checks route_src {node, rail, to_rail,
pinned} (the route as it runs carries the rendered source pin, or none) and far_capture {probe,
src: relay|rail} (the far node saw the probe's requests arrive from an address of the relay
segment, or from the source's own rail address).

Chapter 6 adds the model placement. Its drills run under the Gateway probe, with the serving
Services' endpoints read every second:

    drills:
      probes:
        gateway:   {from: ent-client, gateway: gw-users, models: [chat, staff], interval_s: 1, timeout_s: 100, max_tokens: 8}
        endpoints: {interval_s: 1}
      timing: {lead_s: 20, hold_s: 40, tail_s: 30, return_max_s: 300, whole_polls: 30}
      list:
        - {id: dark-switch, title: ..., dark: {switch: rail-sw1}, probes: [gateway, endpoints]}
        - {id: worker-port, title: ..., worker_port: {model: chat, copy: a, worker: 0}, probes: [gateway, endpoints]}
        - {id: rail-move, title: ..., rail_move: {model: chat, copy: a, worker: 0, to_rail: 5}}

The gateway probe sends one chat completion per model every interval_s from a client through the
Gateway's model route (each request on its own, so a slow answer does not hold the next back),
with the model's key; the plan holds each model's URL and the Secret its key is read from, and
pins the name to the Gateway's VIP when the client's resolver is not in the lab. The endpoints probe
reads the serving namespace's EndpointSlices; the plan holds every Service (one per model, one per
copy) and the servers it should hold. A dark drill under the gateway probe darkens a rail switch as
chapter 5's does; worker_port shuts the one rail switch port facing a copy's worker on the copy's
rail (a worker on its server's node is refused: its RPC never crosses the switch); for both the plan
holds which copies the fault takes out (a copy whose server cannot reach a worker over the dead
rail), which copies stay, and each Service's servers while the fault holds; a fault that would
take every copy of a model is refused. rail_move moves one worker's row in the placement table to
another rail the worker's node holds, at the first free address of that rail's pod range, and
changes nothing in the cluster: the plan holds the row as rendered and as moved.

A break may now act on the serving recipe: pod_rail {pod, to_rail} (the pod re-created as the
recipe renders it, but on another rail, at the first free address of that rail's pod range, with a
rail attachment for it when the table uses none), serve {replace: [pods]} (those pods removed,
then make serve: every pod as the table places it), k8s_show {} (the namespace's pods, Services'
endpoints, the pods' network-status annotations and Warning events, saved), probe_gateway {id,
from, gateway, models, count, interval_s, timeout_s, passes} (chat completions through a Gateway's
model route, each model's key read from its Secret), and the checks endpoints {service, ready} (the
number of ready endpoints a Service holds) and placement {pod, rail} (the rail the pod's
network-status annotation names).

A serving break may also add a route to a pod's rail attachment: pod_route {pod, via} (the pod
re-created at its table address and MAC, but on a copy of its rail attachment named <nad>-route
whose static IPAM adds a route to the cluster's pod network, k8s.pod_cidr, via the on-link rail
address via; its replies to the cluster network then leave on the rail). The record action pod_net
{pod, from: router, capture_s} reads the pod's route table on its node (in the network namespace
whose eth0 holds the pod's IP) and captures the node's rail NIC while a router pod opens a
connection to the pod's HTTP port (the router is the one client the serving namespace's network
policy admits to a server); the check reply_path {pod, leaves: rail|eth0} reads
what pod_net saved: with leaves: rail, the route via the rail address and the pod's replies captured
on the rail with its eth0 address as their source; with leaves: eth0, no such route, no such reply
on the rail and the <nad>-route attachment gone.

Chapter 7 adds the gateway drills, which change the API gateway's keys and routes and Cilium's
Envoy, each put back after:

    drills:
      probes:
        gateway: {from: ent-client, gateway: gw-users, models: [chat, staff], interval_s: 1, timeout_s: 100, max_tokens: 8}
      timing: {lead_s: 10, tail_s: 10, accept_max_s: 300, settle_max_s: 900, whole_polls: 30}
      list:
        - {id: key-lifecycle, title: ..., key_lifecycle: {model: chat, cross: staff, id_base: fd000000}, probes: [gateway]}
        - {id: rejected-code, title: ..., rejected_code: {model: staff, key: chat}, probes: [gateway]}
        - {id: idle-timeout, title: ..., idle_timeout: {from: ent-client, gateway: gw-users, silent_s: 330,
           corrected: {stream_idle_s: 600, request_s: 420, backend_request_s: 400}}, max_passes: 1}

key_lifecycle mints a key for model (its id the id base plus the pass number), follows it to every
API gateway pod and through the VIP, tries it on cross's route, and revokes it; the plan holds both
routes' paths and URLs. rejected_code applies the API gateway's routes ConfigMap with model's
consumer restriction carrying no rejected code or message, then the rendered one again; the plan
holds both ConfigMaps (render/inference.py apisix_routes) and the statuses wanted. idle_timeout
silences the test backend behind gateway for silent_s, which must outlast Envoy's default stream
idle timeout, then applies the corrected chain, which must outlast the silence (the stream idle
timeout, and backendRequest within request); the plan holds the client and URL, the test backend's
pods and its route as rendered and with the corrected timeouts, Cilium's release, chart and values
as rendered and corrected (render/k8s.py cilium_values_doc), and the Gateway's CiliumEnvoyConfig
and lease. max_passes caps the passes a drill runs in. The plan's gateway_layer block holds what the
drills share: the API gateway's selector, port, sidecar and hold file, the key Secret, the key
tool's image and accounts, each model's route path.

A break may now act on the API gateway's keys: key_hold {pod} and key_mint {model, id} in break:,
key_probe {id, model, key, route, expect, wait_s} and key_show {} in record:, gateway_restart {pod:
held} in heal:, the check key_pods {probe, refusing: held|none}, probe_gateway with key: (a named
key, with one model), and a new part, cleanup: (key_revoke {model, id}, a key the break minted), run
after expect_healed: is judged; a break without cleanup renders without the part, as before.

Chapter 1's break moves a security rule's destination and records where the request's SYN went:
panos_api {edit: security, rule, destination: [addresses] | rendered} in break: and heal: (the XML
API's edit of the rule's destination node, which replaces it, where a set would add members beside
the rendered ones; one commit after the part, as for chapter 4's actions; the plan holds the element
and the rendered members), probe_syn {id, from, to, port, count, sport, timeout_s, passes, capture}
in record: (count connects from a client, each from its own pinned source port counting up from
sport, to an address, a node or vip:<gateway>, with the container ports capture names, node:eth,
captured on the lab host around each pass; its connects' shares are probe_share's, as probe_tcp's
are), and the checks syn_at {probe, seen, seen_any, unseen} (the probe's SYNs at every point of
seen, at one point at least of seen_any, at no point of unseen) and tlog_rule {probe, rule, action}
(the traffic log read until it holds the probe's connects, each logged under that rule with that
action).
"""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path

from ..klish_lint import action_problems
from . import RenderError

SCHEMA = 1
PROBES = ("ping", "tcp", "orphan", "public", "rails", "gateway", "endpoints")
PLACE = ("target", "both")
TIMING_DEFAULTS = {
    "lead_s": 10,            # probes running before the cut; placement is read inside it
    "place_s": 4,            # the window placement is read from, ending at the cut
    "place_tries": 5,        # ping probes restarted with new ICMP ids until placed
    "hold_s": 30,            # a shut is held this long, then restored
    "tail_s": 20,            # probes keep running after the restore
    "cut_window_s": 15,      # a loss sent within this many seconds after the cut belongs to it
    "restore_window_s": 25,  # and after the restore, to the restore
    "return_max_s": 600,     # a rebooted switch must return within this
    "return_tail_s": 30,     # probes keep running after the return
    "late_ms": 1000,         # a reply later than this counts as lost (and is reported as late)
    "whole_polls": 60,       # the lab must be whole before a drill: polls, 5 s apart
}
# The firewall drills' timing (chapter 4), in a lab whose list holds one.
FW_TIMING_DEFAULTS = {
    "settle_s": 5,           # after a commit, before the probe runs
    "ntp_wait_s": 300,       # how long the firewall's own NTP is waited for after its route moves
    "log_pause_s": 10,       # between two reads of the traffic log
}
FW_DRILL_KEYS = ("nat_removed", "service_route")
# The rail drills' timing (chapter 5), in a lab whose list holds one.
RAIL_TIMING_DEFAULTS = {
    "lead_s": 10,            # probes running before the cut
    "hold_s": 30,            # the switch is held dark this long, then given no shutdown
    "tail_s": 20,            # probes keep running after the restore
    "whole_polls": 12,       # the rails must be whole before and after a drill: polls, 5 s apart
    "late_ms": 1000,         # a reply later than this counts as lost (and is reported as late)
}
RAIL_DRILL_KEYS = ("dark",)
# The serving drills' timing (chapter 6), in a lab whose list holds one.
SERVE_TIMING_DEFAULTS = {
    "lead_s": 20,            # the probes running before the fault
    "hold_s": 40,            # the fault held this long, then restored
    "tail_s": 30,            # the probes keep running after every Service is whole again
    "return_max_s": 300,     # every Service must be whole again within this after the restore
    "whole_polls": 30,       # the serving layer must be whole before and after a drill: polls, 5 s apart
}
SERVE_DRILL_KEYS = ("worker_port", "rail_move")
# The gateway drills' timing (chapter 7), in a lab whose list holds one.
GW_TIMING_DEFAULTS = {
    "lead_s": 10,            # the gateway probe running before the first change
    "tail_s": 10,            # the probe keeps running after the last change
    "accept_max_s": 300,     # every API gateway pod accepts a minted key, refuses a revoked one, or answers a changed route, within this
    "settle_max_s": 900,     # Cilium's rollouts done and both Gateways answering again within this (the idle-timeout drill)
    "whole_polls": 30,       # the gateway layer must be whole before and after a drill: polls, 5 s apart
}
GW_DRILL_KEYS = ("key_lifecycle", "rejected_code", "idle_timeout")
# Envoy's stream idle timeout when nothing sets it: the Cilium 1.19.7 chart's
# envoy.streamIdleTimeoutDurationSeconds is 300, and Envoy documents five minutes for
# stream_idle_timeout. The idle-timeout drill reads what the Gateway's listener runs; the render
# only refuses a silence that would not outlast this.
DEFAULT_IDLE_S = 300
# The per-pod probe's chat completion: one token, so a probe round costs the model little.
PROBE_PROMPT = "Say yes."
KEY_ID = re.compile(r"^[0-9a-f]{8}$")
CAPTURE_STAGES = ("receive", "firewall", "transmit", "drop")
DEVICE_XPATH = "/config/devices/entry[@name='localhost.localdomain']"
VSYS_XPATH = DEVICE_XPATH + "/vsys/entry[@name='vsys1']"
COUNTER_NAME = re.compile(r"^[a-z][a-z0-9_]*$")


def dumps(obj) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def natural(s: str):
    return [int(t) if t.isdigit() else t for t in re.split(r"([0-9]+)", str(s))]


def bare(a):
    return None if a is None else str(a).split("/")[0]


def _err(where: str, msg: str):
    raise RenderError(f"{where}: {msg}")


def _num(v, where: str, positive=True):
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        _err(where, f"must be a number, got {v!r}")
    if positive and v <= 0:
        _err(where, f"must be above 0, got {v!r}")
    return v


def _node(inv: dict, name, where: str) -> dict:
    n = (inv.get("nodes") or {}).get(str(name))
    if n is None:
        _err(where, f"{name!r} is not a node of {inv.get('lab')}")
    return n


def _nic_switches(inv: dict, name: str) -> list:
    """A bonded node's bond members with the switch each lands on, in member order."""
    n = inv["nodes"][name]
    out = []
    for m in (n.get("bond") or {}).get("members") or []:
        peer = str(((n.get("nics") or {}).get(m) or {}).get("peer") or "")
        sw, _, eth = peer.partition(":")
        native = ((((inv["nodes"].get(sw) or {}).get("nics") or {}).get(eth)) or {}).get("native")
        out.append({"node": name, "eth": m, "switch": sw, "switch_eth": eth, "native": native})
    return out


def _bundle_members(inv: dict, name: str) -> list:
    """An appliance's bundle members (the firewall's ae1 legs) with their switch, in port order."""
    n = inv["nodes"][name]
    out = []
    for eth, nic in sorted((n.get("nics") or {}).items(), key=lambda kv: natural(kv[0])):
        if nic.get("role") != "bundle-member":
            continue
        sw, _, seth = str(nic.get("peer") or "").partition(":")
        native = ((((inv["nodes"].get(sw) or {}).get("nics") or {}).get(seth)) or {}).get("native")
        out.append({"node": name, "eth": eth, "ifname": nic.get("ifname"), "switch": sw, "switch_eth": seth, "native": native})
    return out


def _range_lines(natives: list) -> list:
    """KLISH contexts for a set of Ethernet ports: one interface, or one contiguous range."""
    nums = sorted(int(re.sub(r"^Ethernet", "", x)) for x in natives)
    if len(nums) == 1:
        return [[f"interface Ethernet{nums[0]}"]]
    if nums == list(range(nums[0], nums[-1] + 1)):
        return [[f"interface range Ethernet{nums[0]}-{nums[-1]}"]]
    return [[f"interface Ethernet{k}"] for k in nums]


def _shut_session(natives: list, line: str) -> list:
    out = ["configure terminal"]
    blocks = _range_lines(natives)
    for i, b in enumerate(blocks):
        out += b + [line]
        if i < len(blocks) - 1:
            out.append("exit")
    return out + ["end"]


def _lint(lines: list, where: str) -> None:
    probs = action_problems(lines)
    if probs:
        _err(where, "; ".join(probs))


def _pair(inv: dict) -> dict:
    st = inv.get("stages") or {}
    pairs = st.get("pairs") or []
    if len(pairs) != 1:
        return {}
    members = sorted(n for n, d in inv["nodes"].items() if d.get("pair") == pairs[0])
    out = {"name": pairs[0], "members": members, "peer_link": {}}
    for sw in members:
        d = inv["nodes"][sw]
        mc = d.get("mclag") or {}
        out["domain"] = mc.get("domain")
        out["system_mac"] = mc.get("system_mac")
        pl = (d.get("portchannels") or {}).get(mc.get("peer_link") or "") or {}
        out["peer_link"][sw] = {"portchannel": mc.get("peer_link"), "members": list(pl.get("members") or []),
                                "eths": list(pl.get("member_eths") or [])}
        out.setdefault("source_ip", {})[sw] = mc.get("source_ip")
    return out


def _probes(inv: dict, raw: dict, model=None) -> dict:
    out = {}
    for k, p in sorted((raw or {}).items()):
        where = f"chapter.yaml drills.probes.{k}"
        if k not in PROBES:
            _err(where, f"unknown probe (have {', '.join(PROBES)})")
        if not isinstance(p, dict):
            _err(where, "must be a mapping")
        if k == "gateway":
            out[k] = _gateway_probe(inv, model, p, where)
            continue
        if k == "endpoints":
            out[k] = _endpoints_probe(model, p, where)
            continue
        src = str(p.get("from") or "")
        sn = _node(inv, src, f"{where}.from")
        if k == "rails":
            out[k] = _rails_probe(inv, p, where)
        elif k == "ping":
            dst = str(p.get("to") or "")
            dn = _node(inv, dst, f"{where}.to")
            for nm, n in ((src, sn), (dst, dn)):
                if n.get("kind") != "vm-node" or not n.get("bond"):
                    _err(where, f"{nm} must be a bonded VM guest (the probe is ping -e in the guest, placed on a bond leg)")
            count = int(_num(p.get("count", 8), f"{where}.count"))
            base = int(_num(p.get("id_base", 3100), f"{where}.id_base"))
            if not 0 < base < 65536 - count * 16:
                _err(f"{where}.id_base", "leaves no room for the ICMP ids of every placement try")
            out[k] = {"src": src, "src_addr": bare(sn.get("address")), "dst": dst, "dst_addr": bare(dn.get("address")),
                      "count": count, "id_base": base, "interval_s": _num(p.get("interval_s", 0.1), f"{where}.interval_s"),
                      "capture": _nic_switches(inv, src) + _nic_switches(inv, dst)}
        elif k == "tcp":
            gw = (inv.get("gateways") or {}).get(str(p.get("gateway") or ""))
            if not gw:
                _err(f"{where}.gateway", f"{p.get('gateway')!r} is not a Gateway of {inv.get('lab')}")
            fw = (inv.get("stages") or {}).get("fw")
            if not fw:
                _err(where, "the lab has no firewall, whose bundle legs locate each connect")
            if sn.get("kind") != "client":
                _err(f"{where}.from", f"{src} must be a client container (the connect loop runs its python3)")
            out[k] = {"client": src, "client_addr": bare(sn.get("address")), "gateway": str(p["gateway"]),
                      "dst_addr": bare(gw.get("vip")), "port": int(_num(p.get("port", 443), f"{where}.port")),
                      "interval_s": _num(p.get("interval_s", 0.1), f"{where}.interval_s"),
                      "timeout_s": _num(p.get("timeout_s", 1), f"{where}.timeout_s"),
                      "capture": _bundle_members(inv, fw)}
            if len(out[k]["capture"]) < 2:
                _err(where, f"{fw} has fewer than two bundle members to place connects on")
        elif k == "public":  # a ping from a node to the public address (or another address)
            if sn.get("kind") not in ("vm-node", "bastion", "client"):
                _err(f"{where}.from", f"{src} must be a VM guest or a container with ping")
            out[k] = {"src": src, "src_kind": sn.get("kind"), "src_addr": bare(sn.get("address")),
                      "dst": str(p.get("to") or "public"), "dst_addr": _address(inv, p.get("to") or "public", f"{where}.to"),
                      "count": int(_num(p.get("count", 5), f"{where}.count")),
                      "interval_s": _num(p.get("interval_s", 0.5), f"{where}.interval_s"),
                      "timeout_s": _num(p.get("timeout_s", 1), f"{where}.timeout_s")}
        else:  # orphan: a connect loop to a single-attached address, by bash in the client container
            dst = str(p.get("to") or "")
            dn = _node(inv, dst, f"{where}.to")
            which = str(p.get("address") or "mgmt_if")
            addr = bare(((dn.get(which) or {}) if isinstance(dn.get(which), dict) else {}).get("address"))
            if not addr:
                _err(f"{where}.address", f"{dst} has no {which} address")
            legs = (dn.get(which) or {}).get("nics") or [None]
            if len(legs) > 1:
                _err(f"{where}.to", f"{dst}'s {which} address is dual-attached ({', '.join(legs)}): it has no orphan port to probe")
            nic = legs[0]
            peer = str(((dn.get("nics") or {}).get(nic) or {}).get("peer") or "")
            sw, _, seth = peer.partition(":")
            native = ((((inv["nodes"].get(sw) or {}).get("nics") or {}).get(seth)) or {}).get("native")
            if sn.get("kind") not in ("bastion", "client"):
                _err(f"{where}.from", f"{src} must be a container with bash (the bastion or a client)")
            out[k] = {"client": src, "client_addr": bare(sn.get("address")), "dst": dst, "dst_addr": addr,
                      "port": int(_num(p.get("port", 443), f"{where}.port")),
                      "interval_s": _num(p.get("interval_s", 0.2), f"{where}.interval_s"),
                      "timeout_s": _num(p.get("timeout_s", 1), f"{where}.timeout_s"),
                      "attach": {"nic": nic, "switch": sw, "switch_eth": seth, "native": native}}
    return out


def _relay_node(inv: dict, name, where: str) -> dict:
    n = _node(inv, name, where)
    if n.get("kind") != "vm-node" or not n.get("relay") or not n.get("rails"):
        _err(where, f"{name} must be a VM guest with rails and the in-node relay")
    return n


def _ns_name(n: dict, r: int):
    """The GPU namespace on rail r: the relay's namespaces are listed in rail order."""
    order = sorted(int(x) for x in n.get("rails") or {})
    nss = list((n.get("relay") or {}).get("namespaces") or [])
    return nss[order.index(r)] if r in order and order.index(r) < len(nss) else None


def _rail_addr(n: dict, r: int):
    return bare(((n.get("rails") or {}).get(str(r)) or {}).get("address"))


def _rail_row(inv: dict, sname: str, dname: str, rid: str, kind: str, r: int, t: int, icmp_id: int) -> dict:
    sn, dn = inv["nodes"][sname], inv["nodes"][dname]
    req, rep = (dn.get("rails") or {})[str(t)], (sn.get("rails") or {})[str(r)]
    return {"id": rid, "kind": kind, "rail": r, "to_rail": t, "ns": _ns_name(sn, r), "src": sname, "dst": dname,
            "src_addr": _rail_addr(sn, r), "dst_addr": _rail_addr(dn, t), "icmp_id": icmp_id,
            "request_rail": t, "request_switch": req.get("switch"), "reply_rail": r, "reply_switch": rep.get("switch")}


def _rails_probe(inv: dict, p: dict, where: str) -> dict:
    extra = set(p) - {"from", "to", "id_base", "interval_s", "timeout_s", "cross"}
    if extra:
        _err(where, f"unknown keys {sorted(extra)}")
    src, dst = str(p.get("from") or ""), str(p.get("to") or "")
    sn, dn = _relay_node(inv, src, f"{where}.from"), _relay_node(inv, dst, f"{where}.to")
    if src == dst:
        _err(f"{where}.to", "names another node than from")
    common = sorted({int(x) for x in sn["rails"]} & {int(x) for x in dn["rails"]})
    if not common:
        _err(where, f"{src} and {dst} share no rail")
    base = int(_num(p.get("id_base", 5500), f"{where}.id_base"))
    rows = [_rail_row(inv, src, dst, f"same-{r}", "same", r, r, base + r) for r in common]
    seen = set()
    for i, pair in enumerate(p.get("cross") or []):
        if not (isinstance(pair, list) and len(pair) == 2 and all(isinstance(x, int) and not isinstance(x, bool) for x in pair)):
            _err(f"{where}.cross[{i}]", "a pair [a, b]: from rail a's namespace to the far node's address on rail b")
        a, b = pair
        if a == b or a not in common or b not in common or (a, b) in seen:
            _err(f"{where}.cross[{i}]", f"two different rails both nodes hold, once (have {common})")
        seen.add((a, b))
        rows.append(_rail_row(inv, src, dst, f"cross-{a}-{b}", "cross", a, b, base + 20 + i))
    if not 0 < base < 65536 - 40:
        _err(f"{where}.id_base", "leaves no room for the rows' ICMP ids")
    capture = []
    for name in (src, dst):
        for r in common:
            ri = inv["nodes"][name]["rails"][str(r)]
            capture.append({"node": name, "eth": ri["eth"], "rail": r, "ifname": ri.get("ifname"), "switch": ri.get("switch"),
                            "switch_eth": ri.get("switch_eth"), "native": ri.get("switch_native")})
    return {"src": src, "dst": dst, "rails": common, "rows": rows, "id_base": base,
            "interval_s": _num(p.get("interval_s", 0.2), f"{where}.interval_s"),
            "timeout_s": _num(p.get("timeout_s", 1), f"{where}.timeout_s"), "capture": capture}


def _rail_switches(inv: dict) -> dict:
    out = {}
    for name in inv.get("order") or []:
        n = inv["nodes"][name]
        if n.get("role") != "rail_vlan":
            continue
        natives = sorted((n.get("access") or {}), key=natural)
        out[name] = {"rails": list(n.get("rails") or []), "natives": natives,
                     "eths": [n["access"][x]["eth"] for x in natives]}
    return out


def _rail_drill(inv: dict, d: dict, probes: dict, seen: set) -> dict:
    did = str(d.get("id") or "")
    where = f"chapter.yaml drills.list[{did or '?'}]"
    if not re.match(r"^[a-z][a-z0-9-]*$", did):
        _err(where, "id must be lower case letters, digits and hyphens")
    if did in seen:
        _err(where, "id appears twice")
    seen.add(did)
    extra = set(d) - {"id", "title", "dark", "probes"}
    if extra:
        _err(where, f"unknown keys {sorted(extra)}")
    want = [str(x) for x in d.get("probes") or []]
    if want != ["rails"] or "rails" not in probes:
        _err(f"{where}.probes", "a dark drill runs the rails probe (drills.probes.rails)")
    dk = d.get("dark") or {}
    if set(dk) - {"switch"}:
        _err(f"{where}.dark", f"unknown keys {sorted(set(dk) - {'switch'})}")
    sw = str(dk.get("switch") or "")
    sn = _node(inv, sw, f"{where}.dark.switch")
    if sn.get("role") != "rail_vlan":
        _err(f"{where}.dark.switch", f"{sw} is not a rail switch")
    rs = _rail_switches(inv)
    natives = rs[sw]["natives"]
    if not natives:
        _err(f"{where}.dark.switch", f"{sw} uses no port in this lab")
    pr = probes["rails"]
    dead = sorted(int(x) for x in rs[sw]["rails"] if int(x) in pr["rails"])
    live = [r for r in pr["rails"] if r not in dead]
    if not dead or not live:
        _err(f"{where}.dark.switch", "the probe needs a rail on the dark switch and one off it")
    expect = {row["id"]: ("dark" if row["request_rail"] in dead or row["reply_rail"] in dead else "answered") for row in pr["rows"]}
    if "dark" not in expect.values() or "answered" not in expect.values():
        _err(f"{where}.probes", "the rows must include one the dark switch silences and one it does not")
    out = {"id": did, "title": str(d.get("title") or did), "kind": "dark", "probes": want, "switch": sw, "natives": natives,
           "eths": rs[sw]["eths"], "klish": _shut_session(natives, "shutdown"), "restore": _shut_session(natives, "no shutdown"),
           "dead_rails": dead, "live_rails": live, "live_switches": sorted(x for x in rs if x != sw), "expect": expect}
    _lint(out["klish"] + out["restore"], where)
    return out


# --------------------------------------------------------------------------------------------
# chapter 6: the serving drills


def _serving(model, where: str):
    from . import inference, k8s  # noqa: PLC0415

    if model is None or not inference.enabled(model):
        _err(where, "the lab serves no model through the API gateway (serving off, or no inference block)")
    return k8s.serving_summary(model), inference.settings(model)


def _gateway_target(inv: dict, model, client: str, gateway: str, models: list, where: str) -> dict:
    sv, inf = _serving(model, where)
    cn = _node(inv, client, f"{where}.from")
    if cn.get("kind") != "client":
        _err(f"{where}.from", f"{client} must be a client container (the probe runs its python3)")
    gw = (inv.get("gateways") or {}).get(gateway)
    if not gw:
        _err(f"{where}.gateway", f"{gateway!r} is not a Gateway of {inv.get('lab')}")
    pop = next((x for x in (inv.get("populations") or {}).values() if client in (x.get("clients") or [])), None)
    if pop is None or pop.get("answer_address") != bare(gw.get("vip")):
        _err(f"{where}.from", f"{client}'s population is not answered with {gateway}'s VIP")
    rt = next((r for r in inf["routes"] if r["gateway"] == gateway), None)
    if rt is None:
        _err(f"{where}.gateway", f"{gateway} carries no model route")
    names = [str(x) for x in models]
    if not names:
        _err(f"{where}.models", "names no model")
    out = []
    host = rt["hostnames"][0]
    for m in names:
        mi = next((x for x in inf["models"] if x["name"] == m), None)
        if mi is None or not any(r["model"] in (None, m) for r in rt["rules"]):
            _err(f"{where}.models", f"{m!r} is not a model {gateway}'s route carries")
        out.append({"model": m, "route_id": mi["route_id"], "url": f"https://{host}{mi['path']}/v1/chat/completions",
                    "model_name": f"openai/{m}"})
    resolver = cn.get("resolver")
    resolver_in = bool(resolver and resolver in (inv.get("nodes") or {}))
    return {"client": client, "client_addr": bare(cn.get("address")), "gateway": gateway, "vip": bare(gw.get("vip")),
            "hostname": host, "resolve": None if resolver_in else f"{host}:443:{bare(gw.get('vip'))}", "models": out,
            "keys": {"namespace": inf["namespace"], "secret": inf["keys"]["models"]["secret"]}}


def _gateway_every(out: dict, every, where: str) -> None:
    """every {MODEL: K}: that model's request goes out on every K-th tick of the probe's interval only
    (a slower model at a lower rate); each named model's entry in out["models"] gains "every": K."""
    if every is None:
        return
    if not isinstance(every, dict):
        _err(f"{where}.every", "a mapping of model to a whole number of the probe's intervals")
    names = {m["model"]: m for m in out["models"]}
    for k, v in every.items():
        if str(k) not in names:
            _err(f"{where}.every", f"{k!r} is not one of the probe's models ({', '.join(names)})")
        if isinstance(v, bool) or not isinstance(v, int) or v < 1:
            _err(f"{where}.every.{k}", "a whole number of intervals, 1 or more")
        if v > 1:
            names[str(k)]["every"] = v


def _gateway_probe(inv: dict, model, p: dict, where: str) -> dict:
    extra = set(p) - {"from", "gateway", "models", "interval_s", "timeout_s", "max_tokens", "every"}
    if extra:
        _err(where, f"unknown keys {sorted(extra)}")
    out = _gateway_target(inv, model, str(p.get("from") or ""), str(p.get("gateway") or ""), list(p.get("models") or []), where)
    _gateway_every(out, p.get("every"), where)
    out.update({"interval_s": _num(p.get("interval_s", 1), f"{where}.interval_s"),
                "timeout_s": _num(p.get("timeout_s", 100), f"{where}.timeout_s"),
                "max_tokens": int(_num(p.get("max_tokens", 8), f"{where}.max_tokens"))})
    return out


def _services(sv: dict) -> list:
    rows = sv["placement"]
    out = []
    for m in sv["models"]:
        out.append({"name": m["name"], "kind": "model", "model": m["name"], "copy": None,
                    "servers": [r["pod"] for r in rows if r["model"] == m["name"] and r["role"] == "server"]})
    for m in sv["models"]:
        for c in m["copies"]:
            out.append({"name": f"{m['name']}-{c}", "kind": "copy", "model": m["name"], "copy": c,
                        "servers": [r["pod"] for r in rows if r["model"] == m["name"] and r["copy"] == c and r["role"] == "server"]})
    return out


def _endpoints_probe(model, p: dict, where: str) -> dict:
    extra = set(p) - {"interval_s"}
    if extra:
        _err(where, f"unknown keys {sorted(extra)}")
    sv, _ = _serving(model, where)
    return {"namespace": sv["namespace"], "interval_s": _num(p.get("interval_s", 1), f"{where}.interval_s"), "services": _services(sv)}


def _copies(sv: dict) -> list:
    out = []
    for m in sv["models"]:
        for c in m["copies"]:
            rows = [r for r in sv["placement"] if r["model"] == m["name"] and r["copy"] == c]
            srv = next(r for r in rows if r["role"] == "server")
            out.append({"id": f"{m['name']}-{c}", "model": m["name"], "copy": c, "rail": srv["rail"], "nad": srv["nad"],
                        "server": {"pod": srv["pod"], "node": srv["node"]},
                        "workers": [{"pod": r["pod"], "node": r["node"], "index": r["index"]} for r in rows if r["role"] == "worker"]})
    return out


def _cut(c: dict, node: str, rail: int) -> bool:
    """Whether a copy loses a worker when node's port on rail goes dark: its server there with a worker
    on another node, or a worker there with its server on another node."""
    if c["rail"] != rail:
        return False
    s = c["server"]["node"]
    return (s == node and any(w["node"] != node for w in c["workers"])) or any(w["node"] == node and s != node for w in c["workers"])


def _serve_expect(sv: dict, dead: list, where: str) -> dict:
    copies = _copies(sv)
    live = [c["id"] for c in copies if c["id"] not in dead]
    for m in sv["models"]:
        if not any(c["model"] == m["name"] and c["id"] in live for c in copies):
            _err(where, f"the fault takes every copy of {m['name']}: its users would lose it")
    if not dead:
        _err(where, "the fault takes no copy out")
    dead_servers = {c["server"]["pod"] for c in copies if c["id"] in dead}
    svc = {x["name"]: {"kind": x["kind"], "servers": x["servers"], "while_down": [p for p in x["servers"] if p not in dead_servers]}
           for x in _services(sv)}
    return {"dead_copies": sorted(dead), "live_copies": sorted(live), "services": svc}


def _serve_drill(inv: dict, model, d: dict, probes: dict, seen: set) -> dict:
    did = str(d.get("id") or "")
    where = f"chapter.yaml drills.list[{did or '?'}]"
    if not re.match(r"^[a-z][a-z0-9-]*$", did):
        _err(where, "id must be lower case letters, digits and hyphens")
    if did in seen:
        _err(where, "id appears twice")
    seen.add(did)
    extra = set(d) - {"id", "title", "dark", "worker_port", "rail_move", "probes"}
    if extra:
        _err(where, f"unknown keys {sorted(extra)}")
    faults = [k for k in ("dark", "worker_port", "rail_move") if k in d]
    if len(faults) != 1:
        _err(where, "a serving drill has one fault: dark, worker_port or rail_move")
    sv, _ = _serving(model, where)
    copies = _copies(sv)
    want = [str(x) for x in d.get("probes") or []]
    out = {"id": did, "title": str(d.get("title") or did), "probes": want}
    if faults[0] == "rail_move":
        if want:
            _err(f"{where}.probes", "a rail_move drill changes only the table: it runs no probe")
        rm = d.get("rail_move") or {}
        if set(rm) - {"model", "copy", "worker", "to_rail"}:
            _err(f"{where}.rail_move", f"unknown keys {sorted(set(rm) - {'model', 'copy', 'worker', 'to_rail'})}")
        row = _worker_row(sv, rm, f"{where}.rail_move")
        moved = _moved_row(inv, model, sv, row, rm.get("to_rail"), f"{where}.rail_move.to_rail")
        out.update({"kind": "rail-move", "row": row, "moved": moved})
        return out
    if want != ["gateway", "endpoints"] or "gateway" not in probes or "endpoints" not in probes:
        _err(f"{where}.probes", "a serving drill runs the gateway probe and the endpoints probe (drills.probes.gateway, .endpoints)")
    rs = _rail_switches(inv)
    if faults[0] == "dark":
        dk = d.get("dark") or {}
        if set(dk) - {"switch"}:
            _err(f"{where}.dark", f"unknown keys {sorted(set(dk) - {'switch'})}")
        sw = str(dk.get("switch") or "")
        sn = _node(inv, sw, f"{where}.dark.switch")
        if sn.get("role") != "rail_vlan":
            _err(f"{where}.dark.switch", f"{sw} is not a rail switch")
        natives = rs[sw]["natives"]
        dead_rails = sorted(int(x) for x in rs[sw]["rails"])
        # a copy whose RPC crosses the dark switch (a worker on another node than its server) loses
        # it; a node-local copy on a dark rail keeps its RPC inside the node's macvlan bridge, since
        # a KLISH shutdown drops no carrier at the rail NICs (known limit L9): it stays, and the
        # analysis says so on a KNOWN L9 line (on hardware it would leave too)
        on_dark = [c for c in copies if c["rail"] in dead_rails]
        dead = [c["id"] for c in on_dark if any(w["node"] != c["server"]["node"] for w in c["workers"])]
        in_node = [c["id"] for c in on_dark if c["id"] not in dead]
        out.update({"kind": "serve-dark", "switch": sw, "natives": natives, "eths": rs[sw]["eths"],
                    "klish": _shut_session(natives, "shutdown"), "restore": _shut_session(natives, "no shutdown"),
                    "dead_rails": dead_rails, "faces": None})
    else:
        wp = d.get("worker_port") or {}
        if set(wp) - {"model", "copy", "worker"}:
            _err(f"{where}.worker_port", f"unknown keys {sorted(set(wp) - {'model', 'copy', 'worker'})}")
        row = _worker_row(sv, wp, f"{where}.worker_port")
        cp = next(c for c in copies if c["model"] == row["model"] and c["copy"] == row["copy"])
        if row["node"] == cp["server"]["node"]:
            _err(f"{where}.worker_port", f"{row['pod']} sits on its server's node {row['node']}: its RPC never crosses the rail switch, "
                                         "so shutting its port takes nothing out")
        ri = ((inv["nodes"][row["node"]].get("rails") or {}).get(str(row["rail"]))) or {}
        if not ri.get("switch"):
            _err(f"{where}.worker_port", f"{row['node']} holds no rail {row['rail']}")
        sw, native = ri["switch"], ri["switch_native"]
        dead = [c["id"] for c in copies if _cut(c, row["node"], row["rail"])]
        in_node = []
        out.update({"kind": "worker-port", "switch": sw, "natives": [native], "eths": [ri["switch_eth"]],
                    "klish": _shut_session([native], "shutdown"), "restore": _shut_session([native], "no shutdown"),
                    "dead_rails": [], "faces": {"node": row["node"], "rail": row["rail"], "pod": row["pod"]}})
    _lint(out["klish"] + out["restore"], where)
    out["expect"] = _serve_expect(sv, dead, where)
    out["expect"]["in_node"] = sorted(in_node)
    return out


# chapter 7: the gateway drills


def _gw_layer(model, where: str) -> dict:
    """What every gateway drill and the key break actions share: the API gateway's pods, the key
    Secret, the key tool's image and accounts, each model's route path and the probe's body."""
    sv, inf = _serving(model, where)
    g = inf["gateway"]
    return {"namespace": inf["namespace"], "serving_namespace": sv["namespace"],
            "api_gateway": {"name": g["name"], "selector": f"app.kubernetes.io/name={g['name']}", "port": g["port"],
                            "container": "apisix", "sidecar": "keys", "hold": "/standalone/hold"},
            "router": {"name": inf["router"]["name"], "selector": f"app.kubernetes.io/name={inf['router']['name']}"},
            "keys": {"secret": inf["keys"]["models"]["secret"], "prefix": inf["keys"]["models"]["prefix"], "image": inf["keys_image"],
                     "sa": inf["key_sa"]},
            "probe": {"name": inf["probe"]["name"], "sa": inf["probe"]["sa"], "image": inf["keys_image"]},
            "models": [{"name": m["name"], "route_id": m["route_id"], "path": f"{m['path']}/v1/chat/completions",
                        "key_caller": _key_caller(inf, m["name"])} for m in inf["models"]],
            "rejected": dict(inf["rejected"]), "prompt": PROBE_PROMPT, "gateways": sorted(model.gateways)}


def _key_caller(inf: dict, model_name: str) -> str:
    """The application caller whose keys stand for a model's (the first in the spec's order that may
    call it; the model itself in a lab with no callers): a key field is <caller>.<id>."""
    return next((c["id"] for c in inf.get("callers") or [] if c["kind"] == "application" and model_name in c["models"]), model_name)


def _model_of(inf_models: list, name, where: str) -> dict:
    m = next((x for x in inf_models if x["name"] == str(name or "")), None)
    if m is None:
        _err(where, f"{name!r} is not a model the lab serves ({', '.join(x['name'] for x in inf_models)})")
    return m


def _gw_drill(inv: dict, model, d: dict, probes: dict, seen: set) -> dict:
    did = str(d.get("id") or "")
    where = f"chapter.yaml drills.list[{did or '?'}]"
    if not re.match(r"^[a-z][a-z0-9-]*$", did):
        _err(where, "id must be lower case letters, digits and hyphens")
    if did in seen:
        _err(where, "id appears twice")
    seen.add(did)
    extra = set(d) - {"id", "title", "key_lifecycle", "rejected_code", "idle_timeout", "probes", "max_passes"}
    if extra:
        _err(where, f"unknown keys {sorted(extra)}")
    faults = [k for k in GW_DRILL_KEYS if k in d]
    if len(faults) != 1:
        _err(where, "a gateway drill is one of key_lifecycle, rejected_code or idle_timeout")
    from . import inference, k8s  # noqa: PLC0415

    _, inf = _serving(model, where)
    layer = _gw_layer(model, where)
    want = [str(x) for x in d.get("probes") or []]
    out = {"id": did, "title": str(d.get("title") or did), "probes": want, "max_passes": None}
    if d.get("max_passes") is not None:
        out["max_passes"] = int(_num(d["max_passes"], f"{where}.max_passes"))
    kind = faults[0]
    body = d.get(kind) or {}
    if kind in ("key_lifecycle", "rejected_code"):
        if want != ["gateway"] or "gateway" not in probes:
            _err(f"{where}.probes", "a key drill runs the gateway probe (drills.probes.gateway), which must lose nothing")
        gp = probes["gateway"]
        urls = {m["model"]: m["url"] for m in gp["models"]}
    if kind == "key_lifecycle":
        keys = {"model", "cross", "id_base"}
        if set(body) - keys:
            _err(f"{where}.key_lifecycle", f"unknown keys {sorted(set(body) - keys)}")
        m = _model_of(layer["models"], body.get("model"), f"{where}.key_lifecycle.model")
        c = _model_of(layer["models"], body.get("cross"), f"{where}.key_lifecycle.cross")
        if c["name"] == m["name"]:
            _err(f"{where}.key_lifecycle.cross", "another model than the key's")
        for x in (m, c):
            if x["name"] not in urls:
                _err(f"{where}.key_lifecycle", f"the gateway probe does not reach {x['name']} (drills.probes.gateway.models)")
        base = str(body.get("id_base") or "fd000000")
        if not KEY_ID.match(base) or not base.endswith("0000"):
            _err(f"{where}.key_lifecycle.id_base", "8 hex digits ending in 0000: each pass mints the id base plus its number")
        out.update({"kind": "key-lifecycle", "model": m["name"], "cross": c["name"], "id_base": base, "key_caller": m["key_caller"],
                    "path": m["path"], "cross_path": c["path"], "url": urls[m["name"]], "cross_url": urls[c["name"]]})
        return out
    if kind == "rejected_code":
        keys = {"model", "key"}
        if set(body) - keys:
            _err(f"{where}.rejected_code", f"unknown keys {sorted(set(body) - keys)}")
        m = _model_of(layer["models"], body.get("model"), f"{where}.rejected_code.model")
        kmod = _model_of(layer["models"], body.get("key"), f"{where}.rejected_code.key")
        if kmod["name"] == m["name"]:
            _err(f"{where}.rejected_code.key", "another model's key: the consumer restriction refuses it on this model's route")
        if m["name"] not in urls:
            _err(f"{where}.rejected_code", f"the gateway probe does not reach {m['name']} (drills.probes.gateway.models)")
        cms = [x for x in inference.gateway_docs(inf) if x["kind"] == "ConfigMap" and x["metadata"]["name"] == inf["configmaps"]["routes"]]
        rendered = cms[0]
        variant = json.loads(json.dumps(rendered))
        variant["data"]["apisix.yaml"] = inference.apisix_routes(inf, default_code=m["name"])
        out.update({"kind": "rejected-code", "model": m["name"], "key_model": kmod["name"], "path": m["path"], "url": urls[m["name"]],
                    "configmap": {"name": rendered["metadata"]["name"], "namespace": rendered["metadata"]["namespace"], "key": "apisix.yaml"},
                    "configmap_rendered": rendered, "configmap_default": variant,
                    "expect": {"default": 403, "rendered": inf["rejected"]["code"], "rendered_message": inf["rejected"]["message"]}})
        return out
    # idle_timeout
    if want:
        _err(f"{where}.probes", "the idle-timeout drill runs no background probe: it rolls Cilium's agents, operator and Envoy")
    keys = {"from", "gateway", "silent_s", "corrected"}
    if set(body) - keys:
        _err(f"{where}.idle_timeout", f"unknown keys {sorted(set(body) - keys)}")
    client = str(body.get("from") or "")
    cn = _node(inv, client, f"{where}.idle_timeout.from")
    if cn.get("kind") != "client":
        _err(f"{where}.idle_timeout.from", f"{client} must be a client container (curl, the lab root CA in its bundle)")
    gname = str(body.get("gateway") or "")
    gw = (inv.get("gateways") or {}).get(gname)
    if not gw:
        _err(f"{where}.idle_timeout.gateway", f"{gname!r} is not a Gateway of {inv.get('lab')}")
    pop = next((x for x in (inv.get("populations") or {}).values() if client in (x.get("clients") or [])), None)
    if pop is None or pop.get("answer_address") != bare(gw.get("vip")):
        _err(f"{where}.idle_timeout.from", f"{client}'s population is not answered with {gname}'s VIP")
    tb = k8s.test_backend_settings(model)
    if not tb or gname not in tb["gateways"]:
        _err(f"{where}.idle_timeout.gateway", f"the test backend does not sit behind {gname}")
    silent = int(_num(body.get("silent_s"), f"{where}.idle_timeout.silent_s"))
    if silent <= DEFAULT_IDLE_S:
        _err(f"{where}.idle_timeout.silent_s", f"must outlast Envoy's default stream idle timeout ({DEFAULT_IDLE_S} s)")
    cr = body.get("corrected") or {}
    if set(cr) != {"stream_idle_s", "request_s", "backend_request_s"}:
        _err(f"{where}.idle_timeout.corrected", "stream_idle_s, request_s and backend_request_s")
    idle, req, back = (int(_num(cr[k], f"{where}.idle_timeout.corrected.{k}")) for k in ("stream_idle_s", "request_s", "backend_request_s"))
    if not (silent < back <= req and silent < idle):
        _err(f"{where}.idle_timeout.corrected", f"the corrected chain must outlast the silence: {silent} s < backendRequest {back} s "
                                                f"<= request {req} s, and {silent} s < the stream idle timeout {idle} s")
    host = (gw.get("hostnames") or [None])[0]
    resolver = cn.get("resolver")
    resolver_in = bool(resolver and resolver in (inv.get("nodes") or {}))
    route_name = k8s.route_name(tb, gname)
    docs = k8s.test_backend_docs(model)
    route = next(x for x in docs if x["kind"] == "HTTPRoute" and x["metadata"]["name"] == route_name)
    fixed = json.loads(json.dumps(route))
    for rule in fixed["spec"]["rules"]:
        rule["timeouts"] = {"request": f"{req}s", "backendRequest": f"{back}s"}
    cil = k8s.chart_pin(model, "cilium")
    gws = k8s.gateway_names(model)
    out.update({
        "kind": "idle-timeout", "client": client, "client_addr": bare(cn.get("address")), "gateway": gname, "vip": bare(gw.get("vip")),
        "hostname": host, "resolve": None if resolver_in else f"{host}:443:{bare(gw.get('vip'))}",
        "url": f"https://{host}{tb['path']}?msg=sfab-drill-idle", "silent_s": silent, "default_idle_s": DEFAULT_IDLE_S,
        "corrected": {"stream_idle_s": idle, "request_s": req, "backend_request_s": back},
        "test_backend": {"namespace": str(tb["namespace"]), "deployment": str(tb["name"]), "container": str(tb["name"]),
                         "selector": f"app.kubernetes.io/name={tb['name']}", "port": int(tb["port"]), "replicas": int(tb.get("replicas") or 1),
                         "route": route_name, "route_rendered": route, "route_corrected": fixed},
        "cilium": {"release": k8s.CILIUM_RELEASE, "namespace": k8s.SYSTEM_NS, "chart": k8s.chart_oci(model, cil["name"]),
                   "version": cil["version"], "plain_http": k8s.registry_plain_http(model),
                   "values_rendered": k8s.cilium_values_doc(model), "values_corrected": k8s.cilium_values_doc(model, idle_s=idle),
                   "operator": "deployment/cilium-operator", "agents": "daemonset/cilium", "envoy": "daemonset/cilium-envoy",
                   "config_keys": ["http-stream-idle-timeout", "proxy-stream-idle-timeout-seconds"]},
        "cec": gws[gname]["cec"], "lease": gws[gname]["lease"], "gateways": {g: v["vip"] for g, v in gws.items()},
    })
    return out


def _worker_row(sv: dict, b: dict, where: str) -> dict:
    m, c, w = str(b.get("model") or ""), str(b.get("copy") or ""), b.get("worker")
    if isinstance(w, bool) or not isinstance(w, int):
        _err(f"{where}.worker", "the worker's index in its copy (0, 1, ...)")
    row = next((r for r in sv["placement"] if r["model"] == m and r["copy"] == c and r["role"] == "worker" and r["index"] == w), None)
    if row is None:
        _err(where, f"no worker {w} of copy {m}-{c} in the placement table")
    return {k: row[k] for k in ("pod", "model", "copy", "role", "index", "node", "rail", "nad", "address", "decision", "mac")}


def _free_address(inv: dict, model, sv: dict, rail: int, where: str) -> str:
    import ipaddress  # noqa: PLC0415

    nad = next((n for n in model.k8s.nads if n.rail == rail), None)
    if nad is None:
        _err(where, f"rail {rail} has no pod range")
    used = {str(ipaddress.ip_interface(r["address"]).ip) for r in sv["placement"]}
    a, end = ipaddress.ip_address(nad.range_start), ipaddress.ip_address(nad.range_end)
    plen = ipaddress.ip_network(nad.prefix).prefixlen
    while a <= end:
        if str(a) not in used:
            return f"{a}/{plen}"
        a += 1
    _err(where, f"rail {rail}'s pod range holds no free address")
    return ""


def _moved_row(inv: dict, model, sv: dict, row: dict, to, where: str) -> dict:
    if isinstance(to, bool) or not isinstance(to, int):
        _err(where, "a rail number")
    if to == row["rail"]:
        _err(where, f"{row['pod']} is on rail {to} already")
    ri = ((inv["nodes"][row["node"]].get("rails") or {})).get(str(to))
    if not ri:
        _err(where, f"{row['node']} holds no rail {to}")
    from .k8s import pod_mac  # noqa: PLC0415

    a = _free_address(inv, model, sv, to, where)
    return dict(row, rail=to, nad=f"rail{to}", address=a, mac=pod_mac(model, to, a), master=ri["ifname"],
                switch=ri["switch"], native=ri["switch_native"], vlan=model.rails[to].vlan if to in model.rails else None)


def _address(inv: dict, to, where: str) -> str:
    """public: the firewall's public address; a node: its primary address; else an address."""
    t = str(to or "")
    if t == "public":
        fw = (inv.get("stages") or {}).get("fw")
        pub = ((inv.get("nodes") or {}).get(fw) or {}).get("public") if fw else None
        if not pub:
            _err(where, "public: the lab's firewall has no public address")
        return pub
    n = (inv.get("nodes") or {}).get(t)
    if n is not None:
        if not n.get("address"):
            _err(where, f"{t} has no primary address")
        return bare(n["address"])
    if not re.match(r"^\d+\.\d+\.\d+\.\d+$", t):
        _err(where, f"{t!r} is neither public, a node nor an address")
    return t


def _compact(el) -> str:
    """One rendered PAN-OS element on one line, as the XML API takes it."""
    from .panos import xml  # noqa: PLC0415

    return "".join(line.strip() for line in xml(el).splitlines())


def _fw_view(model, where: str):
    from .panos import view  # noqa: PLC0415

    v = view(model) if model is not None else None
    if v is None:
        _err(where, "the lab has no firewall")
    return v


def _fw_bundle_eths(inv: dict, fw: str) -> list:
    return [m["eth"] for m in _bundle_members(inv, fw)]


def _fw_eth_of(ifname: str):
    m = re.match(r"^ethernet1/(\d+)$", ifname)
    return f"eth{m.group(1)}" if m else None


def nat_entry(v, name: str, where: str) -> dict:
    """A NAT rule of the render: its xpath, its entry on one line and where it goes back."""
    from .panos import nat_rule  # noqa: PLC0415

    names = [n.name for n in v.nat]
    if name not in names:
        _err(where, f"{name!r} is not a NAT rule this lab's firewall carries (have {', '.join(names)})")
    i = names.index(name)
    rules = VSYS_XPATH + "/rulebase/nat/rules"
    place = {"where": "before", "dst": names[i + 1]} if i + 1 < len(names) else {"where": "bottom", "dst": None}
    return {"table": "nat", "rule": name, "rules_xpath": rules, "xpath": f"{rules}/entry[@name='{name}']",
            "element": _compact(nat_rule(v.nat[i])), "place": place, "order": names}


def security_entry(v, name: str, where: str) -> dict:
    from .panos import rule  # noqa: PLC0415

    names = [r.name for r in v.rules]
    if name not in names:
        _err(where, f"{name!r} is not a security rule this lab's firewall carries")
    i = names.index(name)
    rules = VSYS_XPATH + "/rulebase/security/rules"
    place = {"where": "before", "dst": names[i + 1]} if i + 1 < len(names) else {"where": "bottom", "dst": None}
    return {"table": "security", "rule": name, "rules_xpath": rules, "xpath": f"{rules}/entry[@name='{name}']",
            "element": _compact(rule(v.rules[i])), "place": place, "order": names}


def _rule_destination(ent: dict, fw: str, dst, where: str) -> dict:
    """panos_api edit (chapter 1): one security rule's destination replaced through the XML API's
    edit, which replaces the node at the xpath (a set would add members beside the rendered ones):
    the element with the addresses given, or with the render's (rendered, the heal)."""
    m = re.search(r"<destination>.*?</destination>", ent["element"])
    rendered = re.findall(r"<member>([^<]+)</member>", m.group(0)) if m else []
    if not rendered:
        _err(where, f"the rendered rule {ent['rule']} names no destination")
    if dst == "rendered":
        members = rendered
    else:
        members = [str(x) for x in (dst if isinstance(dst, list) else [dst])]
        for x in members:
            if not re.match(r"^\d+\.\d+\.\d+\.\d+(/\d+)?$", x):
                _err(where, f"{x!r}: an address or prefix, or rendered")
        if sorted(members) == sorted(rendered):
            _err(where, f"the rendered destination of {ent['rule']}: a break moves it elsewhere")
    element = "<destination>" + "".join(f"<member>{x}</member>" for x in members) + "</destination>"
    return {"kind": "panos_api", "node": fw, "op": "edit", "table": "security", "rule": ent["rule"], "field": "destination",
            "xpath": ent["xpath"] + "/destination", "element": element, "members": members, "rendered": rendered,
            "order": ent["order"]}


def _service_route_entry(service: str, interface: str, address: str) -> str:
    return (f"<entry name=\"{service}\"><source><interface>{interface}</interface>"
            f"<address>{address}</address></source></entry>")


def _zone_of(v, address: str):
    """The zone of the interface whose connected prefix holds address."""
    from .. import addr  # noqa: PLC0415

    for i in v.interfaces:
        if i.address and i.zone and addr.contains(addr.prefix_of(i.address), address):
            return i.zone
    return None


def _admitting_rule(v, src_zone: str, dst_zone: str, dst: str, port: int, proto: str):
    """The first allow rule of the render that admits proto/port to dst from src_zone to dst_zone."""
    from .. import addr  # noqa: PLC0415

    svcs = {x.name: x for x in v.services}
    for r in v.rules:
        if r.action != "allow":
            continue
        if not ({src_zone, "any"} & set(r.from_zones)) or not ({dst_zone, "any"} & set(r.to_zones)):
            continue
        if not any(c == "any" or addr.contains(c, dst) for c in r.dst_cidrs):
            continue
        from .trace import _svc_ok  # noqa: PLC0415

        ok = _svc_ok(v, r.services, proto, port, r.applications)
        if ok:
            return r.name
    return None


def _fw_drill(inv: dict, model, d: dict, probes: dict, seen: set) -> dict:
    did = str(d.get("id") or "")
    where = f"chapter.yaml drills.list[{did or '?'}]"
    if not re.match(r"^[a-z][a-z0-9-]*$", did):
        _err(where, "id must be lower case letters, digits and hyphens")
    if did in seen:
        _err(where, "id appears twice")
    seen.add(did)
    v = _fw_view(model, where)
    fw = v.fw.name
    out = {"id": did, "title": str(d.get("title") or did), "fw": fw}
    if "nat_removed" in d:
        extra = set(d) - {"id", "title", "nat_removed", "counter", "probe", "capture"}
        if extra:
            _err(where, f"unknown keys {sorted(extra)}")
        ent = nat_entry(v, str(d["nat_removed"]), f"{where}.nat_removed")
        counter = str(d.get("counter") or "")
        if not COUNTER_NAME.match(counter):
            _err(f"{where}.counter", "a global counter name, lower case with underscores")
        pk = str(d.get("probe") or "")
        if probes.get(pk, {}).get("dst") is None or pk != "public":
            _err(f"{where}.probe", "names the public probe (drills.probes.public)")
        pr = probes[pk]
        stages = [str(x) for x in d.get("capture") or ["receive", "drop"]]
        bad = [x for x in stages if x not in CAPTURE_STAGES]
        if bad:
            _err(f"{where}.capture", f"unknown stage(s) {bad} (have {', '.join(CAPTURE_STAGES)})")
        pub_eth = _fw_eth_of(v.fw.public_iface or "")
        out.update({"kind": "fw_nat_removed", "nat": ent, "counter": counter, "probe": pk,
                    "diag": {"source": pr["src_addr"], "destination": pr["dst_addr"], "stages": stages},
                    "capture": {"eths": _fw_bundle_eths(inv, fw) + ([pub_eth] if pub_eth else []),
                                "filter": f"icmp and host {pr['src_addr']} and host {pr['dst_addr']}"}})
    else:
        extra = set(d) - {"id", "title", "service_route", "expect_rule"}
        if extra:
            _err(where, f"unknown keys {sorted(extra)}")
        sr = d.get("service_route") or {}
        if set(sr) - {"service", "interface", "with"}:
            _err(f"{where}.service_route", f"unknown keys {sorted(set(sr) - {'service', 'interface', 'with'})}")
        svc = str(sr.get("service") or "")
        have = {s.service: s for s in v.service_routes}
        if svc not in have:
            _err(f"{where}.service_route.service", f"{svc!r} has no service route in this lab (have {', '.join(sorted(have))})")
        if svc != "ntp":
            _err(f"{where}.service_route.service", "ntp is the service the drill waits for (the firewall polls it by itself)")
        new_if = v.fw.interface(str(sr.get("interface") or ""))
        if new_if is None or new_if.name not in v.l3 or not new_if.address:
            _err(f"{where}.service_route.interface", f"{sr.get('interface')!r} is not an addressed interface of this lab's firewall")
        old = have[svc]
        if new_if.name == old.interface:
            _err(f"{where}.service_route.interface", "is the interface the render already uses")
        server = v.ntp[0]
        exp = str(d.get("expect_rule") or "deny-all-log")
        if exp not in {r.name for r in v.rules}:
            _err(f"{where}.expect_rule", f"{exp!r} is not a security rule this lab's firewall carries")
        from .. import addr  # noqa: PLC0415

        old_addr = addr.ip(old.address).compressed
        old_zone, srv_zone = _zone_of(v, old_addr), _zone_of(v, server)
        admits = _admitting_rule(v, old_zone, srv_zone, server, 123, "udp")
        if admits is None:
            _err(where, f"no rule of the render admits udp/123 from zone {old_zone} to {server} in zone {srv_zone}")
        # the services whose server is the same address move with it (the docstring says why)
        servers = {"dns": tuple(v.dns), "ntp": tuple(v.ntp)}
        ports = {"dns": 53, "ntp": 123}
        want = [str(x) for x in sr.get("with") or []]
        sharing = sorted(x for x, srv in servers.items() if x != svc and x in have and server in srv)
        for x in want:
            if x not in have:
                _err(f"{where}.service_route.with", f"{x!r} has no service route in this lab (have {', '.join(sorted(have))})")
            if x not in sharing:
                _err(f"{where}.service_route.with", f"{x!r} does not share the server {server}")
        missing = [x for x in sharing if x not in want]
        if missing:
            _err(f"{where}.service_route.with", f"{', '.join(missing)} shares the server {server} and must move with {svc} "
                                                "(the firewall keeps one route to a shared server address)")
        withs = []
        for x in want:
            o = have[x]
            oz = _zone_of(v, addr.ip(o.address).compressed)
            adm = _admitting_rule(v, oz, srv_zone, server, ports[x], "udp")
            if adm is None:
                _err(where, f"no rule of the render admits udp/{ports[x]} from zone {oz} to {server} in zone {srv_zone}")
            withs.append({"service": x, "port": ports[x], "server": server,
                          "xpath": f"{DEVICE_XPATH}/deviceconfig/system/route/service/entry[@name='{x}']",
                          "element": _service_route_entry(x, new_if.name, new_if.address),
                          "restore_element": _service_route_entry(x, o.interface, o.address),
                          "restore_rule": adm})
        new_eth = _fw_eth_of(new_if.name)
        filt = " or ".join(f"udp port {p}" for p in [123] + [w["port"] for w in withs])
        out.update({"kind": "fw_service_route", "service": svc, "server": server, "port": 123,
                    "xpath": f"{DEVICE_XPATH}/deviceconfig/system/route/service/entry[@name='{svc}']",
                    "element": _service_route_entry(svc, new_if.name, new_if.address),
                    "restore_element": _service_route_entry(svc, old.interface, old.address),
                    "with": withs, "domain": (inv.get("org") or {}).get("zone") or (inv.get("org") or {}).get("domain"),
                    "from": {"interface": old.interface, "address": old_addr, "zone": old_zone},
                    "to": {"interface": new_if.name, "address": addr.ip(new_if.address).compressed, "zone": new_if.zone},
                    "server_zone": srv_zone, "expect_rule": exp, "restore_rule": admits,
                    "capture": {"eths": _fw_bundle_eths(inv, fw) + ([new_eth] if new_eth else []), "filter": filt}})
    return out


def _drill(inv: dict, d: dict, probes: dict, pair: dict, seen: set) -> dict:
    did = str(d.get("id") or "")
    where = f"chapter.yaml drills.list[{did or '?'}]"
    if not re.match(r"^[a-z][a-z0-9-]*$", did):
        _err(where, "id must be lower case letters, digits and hyphens")
    if did in seen:
        _err(where, "id appears twice")
    seen.add(did)
    want = [str(x) for x in d.get("probes") or []]
    for x in want:
        if x not in probes:
            _err(f"{where}.probes", f"{x!r} is not a probe of drills.probes")
    if "ping" not in want and "tcp" not in want:
        _err(f"{where}.probes", "a drill runs the node-to-node ping or the TCP connect, or both")
    place = {str(k): str(v) for k, v in (d.get("place") or {}).items()}
    for k, v in place.items():
        if k not in ("ping", "tcp") or k not in want:
            _err(f"{where}.place", f"{k!r} is not a placed probe of this drill")
        if v not in PLACE:
            _err(f"{where}.place.{k}", f"must be one of {', '.join(PLACE)}")
    out = {"id": did, "title": str(d.get("title") or did), "probes": want, "place": place,
           "peer_link_counters": bool(d.get("peer_link_counters", False))}
    extra = set(d) - {"id", "title", "probes", "place", "peer_link_counters", "shut", "reboot", "hold_s", "await_return"}
    if extra:
        _err(where, f"unknown keys {sorted(extra)}")
    if "shut" in d and "reboot" in d:
        _err(where, "a drill has one fault: shut or reboot")
    if "shut" in d:
        s = d["shut"] or {}
        if set(s) - {"switch", "portchannel", "keepalive"}:
            _err(f"{where}.shut", f"unknown keys {sorted(set(s) - {'switch', 'portchannel', 'keepalive'})}")
        sw = str(s.get("switch") or "")
        sn = _node(inv, sw, f"{where}.shut.switch")
        if sn.get("kind") != "dell_sonic":
            _err(f"{where}.shut.switch", f"{sw} is not a switch")
        natives, eths, names = [], [], []
        is_peer_link, faces, pcn = False, None, None
        if s.get("portchannel") is not None:
            pcn = f"PortChannel{int(_num(s.get('portchannel'), f'{where}.shut.portchannel'))}"
            pc = (sn.get("portchannels") or {}).get(pcn)
            if not pc:
                _err(f"{where}.shut.portchannel", f"{sw} has no {pcn}")
            natives += list(pc.get("members") or [])
            eths += list(pc.get("member_eths") or [])
            names.append(pcn)
            is_peer_link = pcn == ((pair.get("peer_link") or {}).get(sw) or {}).get("portchannel")
            faces = "the peer switch" if is_peer_link else pc.get("peer_node")
        ka = sn.get("keepalive") or None
        if s.get("keepalive"):
            if not ka:
                _err(f"{where}.shut.keepalive", f"{sw} has no dedicated keepalive link")
            natives.append(ka["port"])
            eths.append(ka["eth"])
            names.append(f"the keepalive link {ka['port']}")
            faces = "the peer switch"
        if not natives:
            _err(f"{where}.shut", "names no port: a portchannel, keepalive: true, or both")
        natives = sorted(natives, key=natural)
        out.update({"kind": "shut", "switch": sw, "portchannel": " and ".join(names), "members": natives,
                    "eths": eths, "faces": faces, "peer_link": is_peer_link, "keepalive_link": bool(s.get("keepalive")),
                    "klish": _shut_session(natives, "shutdown"), "restore": _shut_session(natives, "no shutdown")})
        if "hold_s" in d:
            out["hold_s"] = _num(d["hold_s"], f"{where}.hold_s")
        out["await_return"] = bool(d.get("await_return", False))
        if out["await_return"] and not pair.get("members"):
            _err(f"{where}.await_return", "needs the MCLAG pair (the monitor reads both members)")
        _lint(out["klish"] + out["restore"], where)
    elif "reboot" in d:
        role = str(d.get("reboot") or "")
        if role not in ("standby", "active"):
            _err(f"{where}.reboot", "must be standby or active (read from show mclag brief when the drill runs)")
        if not pair.get("members"):
            _err(where, "a reboot drill needs the MCLAG pair")
        if "hold_s" in d or "await_return" in d:
            _err(where, "hold_s and await_return belong to a shut")
        out.update({"kind": "reboot", "role": role, "command": "sudo reboot", "command_timeout_s": 25})
    else:
        _err(where, "a drill needs a fault: shut or reboot")
    return out


def drills(inv: dict, raw: dict, model=None, ctx=None) -> dict:
    if not isinstance(raw, dict):
        _err("chapter.yaml drills", "must be a mapping")
    extra = set(raw) - {"probes", "timing", "list"}
    if extra:
        _err("chapter.yaml drills", f"unknown keys {sorted(extra)}")
    from . import tenancy  # noqa: PLC0415

    items = list(raw.get("list") or [])
    if items and all(isinstance(d, dict) and any(k in d for k in tenancy.P3_DRILL_KEYS) for d in items):
        # Part III's drills (render/tenancy.py): the lease-holder loss and the isolation drill under
        # load, each carrying its own probes
        if raw.get("probes"):
            _err("chapter.yaml drills.probes", "Part III's drills carry their own probes")
        timing = dict(tenancy.P3_TIMING_DEFAULTS)
        for k, v in (raw.get("timing") or {}).items():
            if k not in timing:
                _err("chapter.yaml drills.timing", f"unknown key {k!r} (have {', '.join(sorted(timing))})")
            timing[k] = _num(v, f"chapter.yaml drills.timing.{k}")
        seen: set = set()
        lst = [tenancy.p3_drill(model, inv, d, seen, ctx) for d in items]
        return {"schema": SCHEMA, "lab": inv.get("lab"), "kind": "part3", "timing": timing, "list": lst}
    if any(isinstance(d, dict) and any(k in d for k in tenancy.P3_DRILL_KEYS) for d in items):
        _err("chapter.yaml drills.list", "Part III's drills run on their own, without the earlier chapters' kinds")
    pair = _pair(inv)
    probes = _probes(inv, raw.get("probes") or {}, model)
    is_serve = [isinstance(d, dict) and (any(k in d for k in SERVE_DRILL_KEYS) or ("dark" in d and "gateway" in (d.get("probes") or [])))
                for d in items]
    is_fw = [isinstance(d, dict) and any(k in d for k in FW_DRILL_KEYS) for d in items]
    is_rail = [isinstance(d, dict) and any(k in d for k in RAIL_DRILL_KEYS) and not sv for d, sv in zip(items, is_serve)]
    is_gw = [isinstance(d, dict) and any(k in d for k in GW_DRILL_KEYS) for d in items]
    defaults = {}
    if not items or not all(f or r or v or g for f, r, v, g in zip(is_fw, is_rail, is_serve, is_gw)):
        defaults.update(TIMING_DEFAULTS)
    if any(is_fw):
        defaults.update(FW_TIMING_DEFAULTS)
    if any(is_rail):
        defaults.update(RAIL_TIMING_DEFAULTS)
    if any(is_serve):
        defaults.update(SERVE_TIMING_DEFAULTS)
    if any(is_gw):
        defaults.update(GW_TIMING_DEFAULTS)
    timing = dict(defaults)
    for k, v in (raw.get("timing") or {}).items():
        if k not in defaults:
            _err("chapter.yaml drills.timing", f"unknown key {k!r} (have {', '.join(sorted(defaults))})")
        timing[k] = _num(v, f"chapter.yaml drills.timing.{k}")
    if "place_s" in timing and timing["place_s"] >= timing["lead_s"]:
        _err("chapter.yaml drills.timing", "place_s must be shorter than lead_s")
    seen: set = set()
    lst = [(_gw_drill(inv, model, d, probes, seen) if g else _serve_drill(inv, model, d, probes, seen) if v
            else _fw_drill(inv, model, d, probes, seen) if f else _rail_drill(inv, d, probes, seen) if r
            else _drill(inv, d, probes, pair, seen))
           for d, f, r, v, g in zip(items, is_fw, is_rail, is_serve, is_gw)]
    if not lst:
        _err("chapter.yaml drills.list", "names no drill")
    bonded = []
    for name in inv.get("order") or []:
        n = inv["nodes"][name]
        if n.get("bond") and n.get("kind") in ("vm-node", "bastion"):
            bonded.append({"node": name, "kind": n["kind"], "bond": n["bond"]["name"], "members": _nic_switches(inv, name)})
    out = {"schema": SCHEMA, "lab": inv.get("lab"), "pair": pair, "probes": probes, "timing": timing,
           "bonded": bonded, "list": lst}
    if any(is_rail) or any(is_serve):
        out["rail_switches"] = _rail_switches(inv)
    if any(is_serve):
        sv, inf = _serving(model, "chapter.yaml drills")
        out["serving"] = {"namespace": sv["namespace"], "copies": _copies(sv), "services": _services(sv),
                          "readiness": dict(sv["readiness"]), "inference_namespace": inf["namespace"],
                          "router": {"attempt_timeout_s": inf["timeouts"]["router_attempt_s"], "retries": inf["timeouts"]["router_retries"]}}
    if any(is_gw):
        out["gateway_layer"] = _gw_layer(model, "chapter.yaml drills")
    return out


# --------------------------------------------------------------------------------------------
# breaks

BREAK_KEYS = {"title", "exercise", "since", "break", "record", "expect_broken", "heal", "expect_healed", "cleanup", "note"}


def _break_action(inv: dict, a, where: str, model=None) -> dict:
    if not isinstance(a, dict) or len(a) != 1:
        _err(where, "each action is a mapping with one key")
    (kind, body), = a.items()
    if kind == "klish":
        node = str((body or {}).get("node") or "")
        n = _node(inv, node, f"{where}.klish.node")
        if n.get("kind") != "dell_sonic":
            _err(f"{where}.klish.node", f"{node} is not a switch")
        ctxl = str(body.get("context") or "").strip()
        lines = [str(x) for x in body.get("lines") or []]
        if not lines:
            _err(f"{where}.klish.lines", "names no line")
        fb = [str(x) for x in body.get("fallback") or []]
        sess = ["configure terminal"] + ([ctxl] if ctxl else []) + lines + ["end"]
        fsess = (["configure terminal"] + ([ctxl] if ctxl else []) + fb + ["end"]) if fb else []
        _lint(sess + fsess, where)
        return {"kind": "klish", "node": node, "context": ctxl, "lines": lines, "session": sess, "fallback": fsess,
                "fallback_lines": fb}
    if kind == "show":
        node = str((body or {}).get("node") or "")
        n = _node(inv, node, f"{where}.show.node")
        lines = [str(x) for x in body.get("lines") or []]
        if n.get("kind") != "dell_sonic" or not lines or not all(x.startswith("show ") for x in lines):
            _err(f"{where}.show", "reads a switch with show lines only")
        _lint(lines, where)
        return {"kind": "show", "node": node, "lines": lines}
    if kind == "probe_tcp":
        b = body or {}
        src, dst = str(b.get("from") or ""), str(b.get("to") or "")
        sn, dn = _node(inv, src, f"{where}.probe_tcp.from"), _node(inv, dst, f"{where}.probe_tcp.to")
        which = str(b.get("address") or "mgmt_if")
        addr = bare(((dn.get(which) or {}) if isinstance(dn.get(which), dict) else {}).get("address"))
        if not addr:
            _err(f"{where}.probe_tcp.address", f"{dst} has no {which} address")
        if sn.get("kind") not in ("bastion", "client"):
            _err(f"{where}.probe_tcp.from", f"{src} must be a container with bash (the bastion or a client)")
        return {"kind": "probe_tcp", "id": str(b.get("id") or "probe"), "node": src, "client_addr": bare(sn.get("address")),
                "dst": dst, "dst_addr": addr, "port": int(_num(b.get("port", 443), f"{where}.probe_tcp.port")),
                "count": int(_num(b.get("count", 60), f"{where}.probe_tcp.count")),
                "interval_s": _num(b.get("interval_s", 0.5), f"{where}.probe_tcp.interval_s"),
                "timeout_s": _num(b.get("timeout_s", 2), f"{where}.probe_tcp.timeout_s"),
                "passes": int(_num(b.get("passes", 1), f"{where}.probe_tcp.passes"))}
    if kind == "restore":
        node = str(body or "")
        n = _node(inv, node, f"{where}.restore")
        if n.get("kind") == "dell_sonic":
            return {"kind": "restore", "node": node}
        if n.get("dns_role") in ("bind-auth", "bind-recursive", "dnsmasq"):
            # a DNS server: its rendered files installed again and reloaded (sfab-dns reload)
            return {"kind": "restore", "node": node, "what": "dns"}
        _err(f"{where}.restore", f"{node}: restore is written for switches (replay plus parity) and DNS servers (the render reloaded)")
    if kind == "vlan_member":
        b = body or {}
        node = str(b.get("node") or "")
        n = _node(inv, node, f"{where}.vlan_member.node")
        if n.get("kind") != "dell_sonic":
            _err(f"{where}.vlan_member.node", f"{node} is not a switch")
        mode = b.get("mode")
        if mode not in (None, "T", "A"):
            _err(f"{where}.vlan_member.mode", "must be T or A")
        return {"kind": "vlan_member", "node": node, "vlan": int(_num(b.get("vlan"), f"{where}.vlan_member.vlan")),
                "port": str(b.get("port") or ""), "present": bool(b.get("present", True)), "mode": mode}
    if kind == "parity":
        node = str((body or {}).get("node") or "")
        n = _node(inv, node, f"{where}.parity.node")
        if n.get("kind") != "dell_sonic":
            _err(f"{where}.parity.node", f"{node} is not a switch")
        return {"kind": "parity", "node": node}
    if kind == "mclag_iface":
        # an MCLAG interface's Local/Remote status as show mclag brief prints it on one pair member
        b = body or {}
        if set(b) - {"node", "portchannel", "local", "remote"}:
            _err(f"{where}.mclag_iface", "node, portchannel, local and remote")
        node = str(b.get("node") or "")
        n = _node(inv, node, f"{where}.mclag_iface.node")
        if n.get("kind") != "dell_sonic" or not n.get("mclag"):
            _err(f"{where}.mclag_iface.node", f"{node} is no MCLAG pair member")
        pc = str(b.get("portchannel") or "")
        pcs = n.get("portchannels") or {}
        if pc not in pcs or not (pcs[pc] or {}).get("mclag"):
            _err(f"{where}.mclag_iface.portchannel", f"{pc!r} is no MCLAG interface of {node} (have "
                 f"{', '.join(k for k, v in pcs.items() if (v or {}).get('mclag'))})")
        st = {k: str(b.get(k) or "") for k in ("local", "remote")}
        if any(v not in ("up", "down") for v in st.values()):
            _err(f"{where}.mclag_iface", "local and remote are up or down")
        return {"kind": "mclag_iface", "node": node, "portchannel": pc, "local": st["local"], "remote": st["remote"],
                "status": f"{st['local']}/{st['remote']}"}
    if kind == "probe_share":
        b = body or {}
        failing = str(b.get("failing") or "")
        if failing not in ("some", "none", "all"):
            _err(f"{where}.probe_share.failing", "must be some (some fail, not all), none or all")
        return {"kind": "probe_share", "probe": str(b.get("probe") or "probe"), "failing": failing}
    if kind in FW_ACTIONS:
        return _fw_break_action(inv, model, kind, body, where)
    if kind in RAIL_ACTIONS:
        return _rail_break_action(inv, model, kind, body, where)
    if kind in SERVE_ACTIONS:
        return _serve_break_action(inv, model, kind, body, where)
    if kind in GW_ACTIONS:
        return _gw_break_action(inv, model, kind, body, where)
    if kind in SYN_ACTIONS:
        return _syn_break_action(inv, model, kind, body, where)
    if kind in DNS_ACTIONS:
        return _dns_break_action(inv, model, kind, body, where)
    if kind in K8S_ACTIONS:
        return _k8s_break_action(inv, model, kind, body, where)
    if kind in LOOKUP_ACTIONS:
        return _lookup_break_action(inv, model, kind, body, where)
    _err(where, f"unknown action {kind!r} (have klish, show, probe_tcp, restore, vlan_member, parity, probe_share, mclag_iface, "
                f"{', '.join(FW_ACTIONS)}, {', '.join(RAIL_ACTIONS)}, {', '.join(SERVE_ACTIONS)}, {', '.join(GW_ACTIONS)}, "
                f"{', '.join(SYN_ACTIONS)}, {', '.join(DNS_ACTIONS)}, {', '.join(K8S_ACTIONS)}, {', '.join(LOOKUP_ACTIONS)})")
    return {}


FW_ACTIONS = ("panos_api", "fw_show", "probe_ping", "probe_http", "counter", "rule_order")
RAIL_ACTIONS = ("relay_route", "ns_show", "probe_rail", "route_src", "far_capture")
SERVE_ACTIONS = ("pod_rail", "pod_route", "serve", "k8s_show", "pod_net", "probe_gateway", "endpoints", "placement", "mac_gone",
                 "reply_path")
GW_ACTIONS = ("key_hold", "key_mint", "key_revoke", "key_probe", "key_show", "gateway_restart", "key_pods")
SYN_ACTIONS = ("probe_syn", "syn_at", "tlog_rule")
DNS_ACTIONS = ("dns_answer", "matrix_cells", "cell_mode")
# Part III: a cluster object changed in place (l2_policy: an audience's announcement policy's
# interfaces; route_rules: a Gateway's model route with another model's rule added), both rendered
# as the merge patch kubectl applies (kind k8s_patch), the heal's the rendered fields; k8s_read: the
# objects behind a Gateway read whole (the policy, the lease, the Gateway, a route)
K8S_ACTIONS = ("l2_policy", "route_rules", "k8s_read")
# Part III: the corporate resolver's forwarding replaced by address= pins (dnsmasq_pin), a client's
# lookups of one name by every stub it has (probe_lookup: dig for A and AAAA, python3's getaddrinfo
# through musl, curl through its own resolver library), and the check lookup_answer
LOOKUP_ACTIONS = ("dnsmasq_pin", "probe_lookup", "lookup_answer")
# what probe_lookup runs on the client, each timed, with its output and exit status kept
LOOKUP_TOOLS = ("dig-a", "dig-aaaa", "getaddrinfo", "curl")
LOOKUP_RCODES = ("NOERROR", "NXDOMAIN", "REFUSED", "SERVFAIL", "timeout")
# where a dns_answer break installs its copy of the server's render, inside the server's container
DNS_BREAK_DIR = "/tmp/sfab-break-dns"
# probe_syn's captures: the TCP headers, an 802.1Q tag and the link header fit
SYN_SNAPLEN = 96


def _syn_point(inv: dict, p, where: str) -> dict:
    """A capture point of probe_syn: node:eth, a container port captured on the lab host."""
    node, _, eth = str(p or "").partition(":")
    n = (inv.get("nodes") or {}).get(node)
    if n is None or n.get("kind") == "vm-node" or eth not in (n.get("nics") or {}):
        _err(where, f"{p!r}: node:eth, a wired container port (not a VM guest's)")
    nic = n["nics"][eth]
    name = (nic.get("ifname") or eth).replace("/", "-")
    return {"id": f"{node}-{name}", "node": node, "eth": eth, "ifname": nic.get("ifname"), "peer": nic.get("peer")}


def _syn_break_action(inv: dict, model, kind: str, body, where: str) -> dict:
    """Chapter 1's break records where a connect's SYN went: probe_syn, and the checks syn_at and
    tlog_rule."""
    b = body or {}
    fw = (inv.get("stages") or {}).get("fw")
    if kind == "probe_syn":
        extra = set(b) - {"id", "from", "to", "port", "count", "sport", "timeout_s", "passes", "capture"}
        if extra:
            _err(f"{where}.probe_syn", f"unknown keys {sorted(extra)}")
        src = str(b.get("from") or "")
        sn = _node(inv, src, f"{where}.probe_syn.from")
        if sn.get("kind") != "client":
            _err(f"{where}.probe_syn.from", f"{src} must be a client container (python3 makes each connect from a pinned port)")
        to = str(b.get("to") or "")
        if to.startswith("vip:"):
            g = (inv.get("gateways") or {}).get(to[4:])
            if not g:
                _err(f"{where}.probe_syn.to", f"{to}: no such Gateway in this lab")
            dst = g["vip"]
        else:
            dst = _address(inv, to, f"{where}.probe_syn.to")
        count = int(_num(b.get("count", 3), f"{where}.probe_syn.count"))
        sport = int(_num(b.get("sport"), f"{where}.probe_syn.sport"))
        passes = int(_num(b.get("passes", 1), f"{where}.probe_syn.passes"))
        # each pass's connects take the next count ports, the heal's after the break's
        if not 1024 < sport or sport + 2 * count * passes >= 65536:
            _err(f"{where}.probe_syn.sport", "an unprivileged port, with room for every connect of every pass of the break and the heal")
        caps = [_syn_point(inv, p, f"{where}.probe_syn.capture") for p in b.get("capture") or []]
        if not caps or len({c["id"] for c in caps}) != len(caps):
            _err(f"{where}.probe_syn.capture", "names the container ports captured around the probe, each once")
        port = int(_num(b.get("port", 443), f"{where}.probe_syn.port"))
        # Part III (chapter 10): a destination the firewall translates (the published address) is
        # captured, and counted, past the firewall under its translated address too
        xdst = None
        if model is not None and model.firewall is not None and src in model.nodes:
            from .decisions import path  # noqa: PLC0415
            from .panos import view  # noqa: PLC0415

            try:
                pr = path(model, view(model), model.nodes[src], dst, port, f"{where}.probe_syn")
            except RenderError:
                pr = {}
            if pr.get("outcome") == "reached" and pr.get("nat_rule") and pr.get("at") and pr["at"] != dst:
                xdst = pr["at"]
        hosts = f"host {dst}" if xdst is None else f"(host {dst} or host {xdst})"
        filt = f"host {bare(sn.get('address'))} and {hosts} and tcp port {port}"
        out = {"kind": "probe_syn", "id": str(b.get("id") or "syn"), "node": src, "client_addr": bare(sn.get("address")), "to": to,
               "dst_addr": dst, "port": port, "count": count, "sport": sport,
               "timeout_s": _num(b.get("timeout_s", 5), f"{where}.probe_syn.timeout_s"), "passes": passes, "capture": caps,
               "filter": f"({filt}) or (vlan and ({filt}))", "snaplen": SYN_SNAPLEN}
        if xdst is not None:
            out["translated_addr"] = xdst
        return out
    if kind == "syn_at":
        extra = set(b) - {"probe", "seen", "seen_any", "unseen"}
        if extra or not b.get("probe") or not (b.get("seen") or b.get("seen_any") or b.get("unseen")):
            _err(f"{where}.syn_at", "probe: a probe_syn, and seen, seen_any or unseen: its capture points as node:eth")
        return {"kind": "syn_at", "probe": str(b["probe"]), **{k: [str(x) for x in b.get(k) or []] for k in ("seen", "seen_any", "unseen")}}
    # tlog_rule
    if not fw:
        _err(where, "the lab has no firewall")
    if set(b) - {"probe", "rule", "action"} or not b.get("probe") or not b.get("rule") or b.get("action") not in ("allow", "deny"):
        _err(f"{where}.tlog_rule", "probe: a probe_syn, rule: the rule its connects must be logged under, action: allow or deny")
    v = _fw_view(model, where)
    if str(b["rule"]) not in {r.name for r in v.rules}:
        _err(f"{where}.tlog_rule.rule", f"{b['rule']!r} is not a security rule this lab's firewall carries")
    return {"kind": "tlog_rule", "node": fw, "probe": str(b["probe"]), "rule": str(b["rule"]), "action": str(b["action"])}


def _dns_break_action(inv: dict, model, kind: str, body, where: str) -> dict:
    """Chapter 2's break moves a resolver view's answer: dns_answer (a view's forward zone with some
    names answering another address, installed in place of the rendered file and reloaded); the
    probe matrix_cells (cells of the lab's matrix tried as matrix.sh tries them, common/matrix/) and
    the check cell_mode (the mode a cell's evidence shows)."""
    from . import decisions  # noqa: PLC0415
    from . import dns as D  # noqa: PLC0415

    b = body or {}
    if kind == "dns_answer":
        extra = set(b) - {"node", "view", "names", "answer"}
        if extra or not b.get("view") or not b.get("names") or not b.get("answer"):
            _err(f"{where}.dns_answer", "node: a DNS server, view: one of its views, names: hostnames of the zone, answer: vip:<gateway> or public")
        node = str(b.get("node") or "")
        n = _node(inv, node, f"{where}.dns_answer.node")
        if n.get("dns_role") != "bind-auth":
            _err(f"{where}.dns_answer.node", f"{node} is no authoritative server")
        h = model.nodes.get(node)
        view = next((x for x in (model.dns.views if model.dns else ()) if x.name == str(b["view"]) and x.server == node), None)
        if view is None:
            _err(f"{where}.dns_answer.view", f"{b['view']!r} is not a view {node} serves as its primary")
        ref = str(b["answer"])
        if ref == "public":
            fw = model.firewall
            addr_ = fw.public if fw is not None else None
        elif ref.startswith("vip:") and ref[4:] in model.gateways:
            addr_ = model.gateways[ref[4:]].vip
        else:
            addr_ = None
        if not addr_:
            _err(f"{where}.dns_answer.answer", f"{ref!r}: vip:<a Gateway of this lab> or public")
        names = [model.org.fqdn(str(x)) for x in b["names"]]
        override = {x: addr_ for x in names}
        ctx = type("Ctx", (), {"profile_file": staticmethod(lambda m: f"spec/profile-{m.profile}.yaml")})()
        try:
            f, text = D.answered_zone(model, h, view, override, f"break: {', '.join(names)} answer {addr_} ({ref}) in this view", ctx)
        except D.DnsRenderError as e:
            _err(f"{where}.dns_answer", str(e))
        if addr_ == view.answer_address:
            _err(f"{where}.dns_answer.answer", f"view {view.name} answers {addr_} already: the break would change nothing")
        return {"kind": "dns_answer", "node": node, "view": view.name, "names": names, "answer": ref, "address": addr_,
                "rendered": view.answer_address, "file": f, "content": text, "dir": DNS_BREAK_DIR}
    if not decisions.on(model):
        _err(where, f"{kind} needs the lab's matrix (chapter.yaml decisions: true)")
    if kind == "matrix_cells":
        extra = set(b) - {"id", "cells"}
        cells = [str(x) for x in b.get("cells") or []]
        if extra or not cells:
            _err(f"{where}.matrix_cells", "id: the probe's name, cells: <population>/<column> of the lab's matrix")
        have = {c["id"] for c in decisions.matrix(model)["cells"]}
        bad = [c for c in cells if c not in have]
        if bad or len(set(cells)) != len(cells):
            _err(f"{where}.matrix_cells.cells", f"each a cell of the lab's matrix, once (not one: {', '.join(bad) or 'a repeat'})")
        return {"kind": "matrix_cells", "id": str(b.get("id") or "cells"), "cells": cells}
    # cell_mode
    extra = set(b) - {"probe", "cell", "mode", "rule"}
    if extra or not b.get("probe") or not b.get("cell") or str(b.get("mode")) not in decisions.MODES:
        _err(f"{where}.cell_mode", f"probe: a matrix_cells, cell: one of its cells, mode: one of {', '.join(decisions.MODES)}, rule: for a log line")
    out = {"kind": "cell_mode", "probe": str(b["probe"]), "cell": str(b["cell"]), "mode": str(b["mode"])}
    if b.get("rule"):
        if out["mode"] != "log-line":
            _err(f"{where}.cell_mode.rule", "names the rule of a log line")
        v = _fw_view(model, where)
        if str(b["rule"]) not in {r.name for r in v.rules}:
            _err(f"{where}.cell_mode.rule", f"{b['rule']!r} is not a security rule this lab's firewall carries")
        out["rule"] = str(b["rule"])
    return out


def _k8s_gateway(model, gname, where: str):
    g = model.gateways.get(str(gname or "")) if model is not None else None
    if g is None:
        _err(where, f"{gname!r} is not a Gateway of this lab")
    return g


def _k8s_break_action(inv: dict, model, kind: str, body, where: str) -> dict:
    """Part III's cluster break actions: l2_policy and route_rules render to k8s_patch (the object,
    the merge patch kubectl patch --type merge applies, and what it changes), k8s_read to the
    objects read whole."""
    from . import inference  # noqa: PLC0415
    from . import k8s as K  # noqa: PLC0415

    b = body or {}
    if model is None or model.k8s is None:
        _err(where, f"{kind} needs the lab's cluster")
    if kind == "l2_policy":
        if set(b) - {"gateway", "interfaces"} or not b.get("gateway") or b.get("interfaces") in (None, [], ""):
            _err(f"{where}.l2_policy", "gateway: a Gateway, interfaces: the patterns the policy names, or rendered")
        g = _k8s_gateway(model, b["gateway"], f"{where}.l2_policy.gateway")
        if K.l2_policy_mode(model) != "per-audience":
            _err(f"{where}.l2_policy", "the lab's announcement policy is one for every Gateway: a break would touch them all")
        name = K.l2_policies(model)[g.name]
        rendered = list(model.k8s.l2_announce.get("interfaces") or [])
        want = rendered if b["interfaces"] == "rendered" else [str(x) for x in b["interfaces"]]
        if b["interfaces"] != "rendered" and want == rendered:
            _err(f"{where}.l2_policy.interfaces", "the rendered interfaces already: the break would change nothing")
        for x in want:
            try:
                re.compile(x)
            except re.error as e:
                _err(f"{where}.l2_policy.interfaces", f"{x!r} is not a regular expression ({e})")
        return {"kind": "k8s_patch", "what": "l2_policy", "resource": "ciliuml2announcementpolicies.cilium.io", "namespace": None,
                "name": name, "gateway": g.name, "patch": {"spec": {"interfaces": want}}, "rendered": rendered == want,
                "summary": f"policy {name} (the {g.audience} audience's, {g.name}) names interfaces {', '.join(want)}"
                           + (" (rendered)" if rendered == want else f" (rendered {', '.join(rendered)})")}
    if kind == "route_rules":
        if set(b) - {"route", "add"} or not b.get("route") or b.get("add") in (None, [], ""):
            _err(f"{where}.route_rules", "route: a Gateway's model route (models-<gateway>), add: the models whose rules it gains, or rendered")
        if not inference.enabled(model):
            _err(where, "route_rules needs the API gateway's model routes (serving on)")
        st = inference.settings(model)
        rt = next((x for x in st["routes"] if x["name"] == str(b["route"])), None)
        if rt is None:
            _err(f"{where}.route_rules.route", f"{b['route']!r} is not one of {', '.join(x['name'] for x in st['routes'])}")
        if any(x["model"] is None for x in rt["rules"]):
            _err(f"{where}.route_rules.route", f"{rt['name']} carries the bare prefix: every model is on it already")
        add = [] if b["add"] == "rendered" else [str(x) for x in b["add"]]
        have = [x["model"] for x in rt["rules"]]
        models = {m["name"]: m for m in st["models"]}
        for x in add:
            if x not in models or x in have:
                _err(f"{where}.route_rules.add", f"{x!r}: a model the lab serves whose rule {rt['name']} does not carry")
        st2 = json.loads(json.dumps(st))
        rt2 = next(x for x in st2["routes"] if x["name"] == rt["name"])
        rt2["rules"] += [{"path": models[x]["path"], "model": x} for x in add]
        doc = next(d for d in inference.route_docs(model, st2) if d["metadata"]["name"] == rt["name"])
        return {"kind": "k8s_patch", "what": "route_rules", "resource": "httproutes.gateway.networking.k8s.io",
                "namespace": st["namespace"], "name": rt["name"], "gateway": rt["gateway"],
                "patch": {"spec": {"rules": doc["spec"]["rules"]}}, "rendered": not add, "models": have + add,
                "summary": f"HTTPRoute {st['namespace']}/{rt['name']} ({rt['gateway']}) carries the rules of {', '.join(have + add)}"
                           + (" (rendered)" if not add else f" (rendered {', '.join(have)})")}
    # k8s_read
    objs = [str(x) for x in b.get("objects") or []]
    if set(b) - {"objects"} or not objs:
        _err(f"{where}.k8s_read", "objects: what to read whole, each l2_policy:<gateway>, lease:<gateway>, gateway:<gateway> or route:<name>")
    out = []
    names = K.gateway_names(model)
    for o in objs:
        t, _, v = o.partition(":")
        w = f"{where}.k8s_read.objects"
        if t == "l2_policy":
            g = _k8s_gateway(model, v, w)
            out.append({"id": o, "resource": "ciliuml2announcementpolicies.cilium.io", "namespace": None, "name": K.l2_policies(model)[g.name]})
        elif t == "lease":
            g = _k8s_gateway(model, v, w)
            ns, _, nm = names[g.name]["lease"].partition("/")
            out.append({"id": o, "resource": "leases.coordination.k8s.io", "namespace": ns, "name": nm})
        elif t == "gateway":
            g = _k8s_gateway(model, v, w)
            out.append({"id": o, "resource": "gateways.gateway.networking.k8s.io", "namespace": K.gateway_namespace(model), "name": g.name})
            ns, _, nm = names[g.name]["service"].partition("/")
            out.append({"id": f"service:{g.name}", "resource": "services", "namespace": ns, "name": nm})
        elif t == "route":
            st = inference.settings(model) if inference.enabled(model) else None
            rt = next((x for x in (st or {}).get("routes") or [] if x["name"] == v), None)
            if rt is None:
                _err(w, f"{o!r}: no model route {v!r}")
            out.append({"id": o, "resource": "httproutes.gateway.networking.k8s.io", "namespace": st["namespace"], "name": v})
        else:
            _err(w, f"{o!r}: l2_policy:, lease:, gateway: or route:")
    return {"kind": "k8s_read", "objects": out}


def _lookup_break_action(inv: dict, model, kind: str, body, where: str) -> dict:
    """Part III's resolver break (chapter 9): dnsmasq_pin, probe_lookup and the check lookup_answer."""
    from . import dns as D  # noqa: PLC0415

    b = body or {}
    if kind == "dnsmasq_pin":
        if set(b) - {"node", "names"} or not b.get("node") or not b.get("names"):
            _err(f"{where}.dnsmasq_pin", "node: the corporate resolver (dnsmasq), names: hostnames of the platform zone to pin")
        node = str(b["node"])
        n = _node(inv, node, f"{where}.dnsmasq_pin.node")
        if n.get("dns_role") != "dnsmasq" or model is None or model.dns is None:
            _err(f"{where}.dnsmasq_pin.node", f"{node} is no dnsmasq resolver")
        h = model.nodes[node]
        r = model.dns.resolver_of(node)
        ref = D.view_for(model, h.primary)
        if ref is None or not ref.answer_address:
            _err(f"{where}.dnsmasq_pin.node", f"no view answers {node}")
        names = [model.org.fqdn(str(x)) for x in b["names"]]
        held = model.dns.names_of(ref)
        for x in names:
            if x not in held:
                _err(f"{where}.dnsmasq_pin.names", f"{x} is no name view {ref.name} answers for {node}")
        ctx = type("Ctx", (), {"profile_file": staticmethod(lambda m: f"spec/profile-{m.profile}.yaml"),
                               "warn": staticmethod(lambda *_a: None)})()
        text = D.dnsmasq_conf(model, h, r, ctx)
        kept = [x for x in text.splitlines() if not x.startswith(f"server=/{model.dns.zone}/")]
        if len(kept) == len(text.splitlines()):
            _err(f"{where}.dnsmasq_pin", f"{node}'s render forwards no zone to remove")
        kept.append(f"# break: the platform's zone no longer forwarded; {', '.join(names)} pinned with address=, and no local= for the platform's zone")
        kept += [f"address=/{x}/{ref.answer_address}" for x in names]
        return {"kind": "dnsmasq_pin", "node": node, "names": names, "address": ref.answer_address, "view": ref.name,
                "file": "dnsmasq.conf", "content": "\n".join(kept) + "\n", "dir": DNS_BREAK_DIR}
    if kind == "probe_lookup":
        if set(b) - {"id", "from", "name", "path", "tools", "timeout_s"} or not b.get("from") or not b.get("name"):
            _err(f"{where}.probe_lookup", "id, from: a client, name: a hostname of the platform zone, path, tools, timeout_s")
        src = str(b["from"])
        sn = _node(inv, src, f"{where}.probe_lookup.from")
        if sn.get("kind") != "client":
            _err(f"{where}.probe_lookup.from", f"{src} must be a client container (dig, python3 and curl)")
        tools = [str(x) for x in b.get("tools") or LOOKUP_TOOLS]
        bad = [x for x in tools if x not in LOOKUP_TOOLS]
        if bad or len(set(tools)) != len(tools):
            _err(f"{where}.probe_lookup.tools", f"each of {', '.join(LOOKUP_TOOLS)}, once")
        host = str(b["name"])
        if not re.match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", host):
            _err(f"{where}.probe_lookup.name", "a single DNS label under the platform zone")
        path = str(b.get("path") or "/echo")
        if not path.startswith("/") or " " in path or "'" in path:
            _err(f"{where}.probe_lookup.path", "must start with / and hold no space or quote")
        fqdn = model.org.fqdn(host) if model is not None else host
        return {"kind": "probe_lookup", "id": str(b.get("id") or "lookup"), "node": src, "name": fqdn, "tools": tools,
                "url": f"https://{fqdn}{path}", "timeout_s": _num(b.get("timeout_s", 60), f"{where}.probe_lookup.timeout_s")}
    # lookup_answer
    keys = {"probe", "type", "rcode", "answers", "tool", "ok"}
    if set(b) - keys or not b.get("probe"):
        _err(f"{where}.lookup_answer", "probe: a probe_lookup, and type (A or AAAA) with rcode and answers, or tool with ok")
    if b.get("tool"):
        if b["tool"] not in ("getaddrinfo", "curl") or not isinstance(b.get("ok"), bool) or b.get("type") or b.get("rcode"):
            _err(f"{where}.lookup_answer", "tool: getaddrinfo or curl, ok: true or false (whether it resolved and, for curl, connected)")
        return {"kind": "lookup_answer", "probe": str(b["probe"]), "tool": str(b["tool"]), "ok": bool(b["ok"])}
    if str(b.get("type")) not in ("A", "AAAA") or str(b.get("rcode")) not in LOOKUP_RCODES:
        _err(f"{where}.lookup_answer", f"type: A or AAAA, rcode: one of {', '.join(LOOKUP_RCODES)}")
    ans = b.get("answers")
    if ans is not None and (not isinstance(ans, int) or ans < 0):
        _err(f"{where}.lookup_answer.answers", "how many records the answer section holds")
    return {"kind": "lookup_answer", "probe": str(b["probe"]), "type": str(b["type"]), "rcode": str(b["rcode"]), "answers": ans}


def _gw_break_action(inv: dict, model, kind: str, body, where: str) -> dict:
    """The API gateway's key break actions and checks (chapter 7)."""
    b = body or {}
    layer = _gw_layer(model, where)
    base = {"namespace": layer["namespace"], "api_gateway": layer["api_gateway"], "keys": layer["keys"]}
    if kind == "key_hold":
        if set(b) - {"pod"}:
            _err(f"{where}.key_hold", "pod: the API gateway pod's place among them by name (0, 1, ...)")
        i = b.get("pod")
        if isinstance(i, bool) or not isinstance(i, int) or i < 0:
            _err(f"{where}.key_hold.pod", "the pod's place among the API gateway's pods by name (0, 1, ...)")
        return dict(base, kind="key_hold", index=i)
    if kind in ("key_mint", "key_revoke"):
        if set(b) - {"model", "id"}:
            _err(f"{where}.{kind}", "model: the key's model, id: its 8 hex digits")
        m = _model_of(layer["models"], b.get("model"), f"{where}.{kind}.model")
        kid = str(b.get("id") or "")
        if not KEY_ID.match(kid):
            _err(f"{where}.{kind}.id", "8 hex digits")
        return dict(base, kind=kind, model=m["name"], id=kid, field=f"{m['key_caller']}.{kid}")
    if kind == "key_probe":
        keys = {"id", "model", "key", "route", "expect", "wait_s"}
        if set(b) - keys:
            _err(f"{where}.key_probe", f"unknown keys {sorted(set(b) - keys)}")
        km = _model_of(layer["models"], b.get("model"), f"{where}.key_probe.model")
        rm = _model_of(layer["models"], b.get("route") or km["name"], f"{where}.key_probe.route")
        kid = b.get("key", "first")
        if kid != "first" and not KEY_ID.match(str(kid)):
            _err(f"{where}.key_probe.key", "first (the model's first key) or a key's 8 hex digits")
        exp = int(_num(b.get("expect", 200), f"{where}.key_probe.expect"))
        return dict(base, kind="key_probe", id=str(b.get("id") or "pods"), model=km["name"], route=rm["name"], path=rm["path"],
                    key=str(kid), field=None if kid == "first" else f"{km['key_caller']}.{kid}", expect=exp,
                    wait_s=int(_num(b.get("wait_s", 240), f"{where}.key_probe.wait_s")), probe=layer["probe"], prompt=layer["prompt"])
    if kind == "key_show":
        if b:
            _err(f"{where}.key_show", "takes no settings: the key Secret's fields and fingerprints and each API gateway pod's sidecar log")
        return dict(base, kind="key_show")
    if kind == "gateway_restart":
        if set(b) - {"pod"} or b.get("pod") != "held":
            _err(f"{where}.gateway_restart", "pod: held (the API gateway pod a key_hold action of break: holds)")
        return dict(base, kind="gateway_restart", pod="held", deployment=layer["api_gateway"]["name"])
    # key_pods
    if set(b) - {"probe", "refusing"} or b.get("refusing") not in ("held", "none"):
        _err(f"{where}.key_pods", "probe: a key_probe of record:, refusing: held (only the held pod refuses the key) or none")
    return {"kind": "key_pods", "probe": str(b.get("probe") or ""), "refusing": str(b["refusing"])}


def _serve_break_action(inv: dict, model, kind: str, body, where: str) -> dict:
    """The serving recipe's break actions and checks (chapter 6)."""
    b = body or {}
    sv, _ = _serving(model, where)
    pods = {r["pod"]: r for r in sv["placement"]}
    if kind == "pod_rail":
        if set(b) - {"pod", "to_rail"}:
            _err(f"{where}.pod_rail", f"unknown keys {sorted(set(b) - {'pod', 'to_rail'})}")
        row = pods.get(str(b.get("pod") or ""))
        if row is None:
            _err(f"{where}.pod_rail.pod", f"{b.get('pod')!r} is not a pod of the placement table")
        row = {k: row[k] for k in ("pod", "model", "copy", "role", "index", "node", "rail", "nad", "address", "decision", "mac")}
        moved = _moved_row(inv, model, sv, row, b.get("to_rail"), f"{where}.pod_rail.to_rail")
        new_nad = moved["nad"] not in {n["name"] for n in sv["nads"]}
        return {"kind": "pod_rail", "node": row["node"], "pod": row["pod"], "row": row, "moved": moved, "new_nad": new_nad,
                "namespace": sv["namespace"]}
    if kind == "serve":
        if set(b) - {"replace"}:
            _err(f"{where}.serve", f"unknown keys {sorted(set(b) - {'replace'})}")
        rep = [str(x) for x in b.get("replace") or []]
        for x in rep:
            if x not in pods:
                _err(f"{where}.serve.replace", f"{x!r} is not a pod of the placement table")
        return {"kind": "serve", "replace": rep, "namespace": sv["namespace"]}
    if kind == "k8s_show":
        if b:
            _err(f"{where}.k8s_show", "takes no settings: the serving namespace's pods, endpoints, network-status and events")
        return {"kind": "k8s_show", "namespace": sv["namespace"]}
    if kind == "probe_gateway":
        keys = {"id", "from", "gateway", "models", "count", "interval_s", "timeout_s", "passes", "max_tokens", "key", "every"}
        if set(b) - keys:
            _err(f"{where}.probe_gateway", f"unknown keys {sorted(set(b) - keys)}")
        out = _gateway_target(inv, model, str(b.get("from") or ""), str(b.get("gateway") or ""), list(b.get("models") or []),
                              f"{where}.probe_gateway")
        _gateway_every(out, b.get("every"), f"{where}.probe_gateway")
        kid = b.get("key")
        out["key"] = None
        if kid is not None:
            if not KEY_ID.match(str(kid)) or len(out["models"]) != 1:
                _err(f"{where}.probe_gateway.key", "a key's 8 hex digits, with one model")
            sv_, inf_ = _serving(model, where)
            out["key"] = f"{_key_caller(inf_, out['models'][0]['model'])}.{kid}"
        out.update({"kind": "probe_gateway", "id": str(b.get("id") or "gateway"), "node": out["client"],
                    "count": int(_num(b.get("count", 10), f"{where}.probe_gateway.count")),
                    "interval_s": _num(b.get("interval_s", 1), f"{where}.probe_gateway.interval_s"),
                    "timeout_s": _num(b.get("timeout_s", 100), f"{where}.probe_gateway.timeout_s"),
                    "max_tokens": int(_num(b.get("max_tokens", 8), f"{where}.probe_gateway.max_tokens")),
                    "passes": int(_num(b.get("passes", 1), f"{where}.probe_gateway.passes"))})
        return out
    if kind == "endpoints":
        if set(b) - {"service", "ready"}:
            _err(f"{where}.endpoints", "service: a serving Service, ready: how many ready endpoints it holds")
        svcs = {x["name"]: x for x in _services(sv)}
        name = str(b.get("service") or "")
        if name not in svcs:
            _err(f"{where}.endpoints.service", f"{name!r} is not a Service of the recipe ({', '.join(sorted(svcs))})")
        ready = b.get("ready")
        if isinstance(ready, bool) or not isinstance(ready, int) or not 0 <= ready <= len(svcs[name]["servers"]):
            _err(f"{where}.endpoints.ready", f"0 to {len(svcs[name]['servers'])}, the Service's servers")
        return {"kind": "endpoints", "service": name, "ready": ready, "servers": svcs[name]["servers"], "namespace": sv["namespace"]}
    if kind == "pod_route":
        if set(b) - {"pod", "via"}:
            _err(f"{where}.pod_route", f"unknown keys {sorted(set(b) - {'pod', 'via'})}")
        row = pods.get(str(b.get("pod") or ""))
        if row is None:
            _err(f"{where}.pod_route.pod", f"{b.get('pod')!r} is not a pod of the placement table")
        nad = next(n for n in sv["nads"] if n["name"] == row["nad"])
        net = ipaddress.ip_network(nad["prefix"])
        via = str(b.get("via") or "")
        try:
            gw = ipaddress.ip_address(via)
        except ValueError:
            _err(f"{where}.pod_route.via", f"{via!r} is not an address")
        if gw not in net or via == bare(row["address"]) or gw in (net.network_address, net.broadcast_address):
            _err(f"{where}.pod_route.via", f"{via} is not another host of {row['pod']}'s rail prefix {net} (on-link)")
        cidr = str(((inv.get("k8s") or {}).get("pod_cidr")) or "")
        if not cidr:
            _err(f"{where}.pod_route", "the lab has no pod network (k8s.pod_cidr)")
        row = {k: row[k] for k in ("pod", "model", "copy", "role", "index", "node", "rail", "nad", "address", "decision", "mac")}
        return {"kind": "pod_route", "node": row["node"], "pod": row["pod"], "row": row, "nad": f"{row['nad']}-route",
                "master": nad["master"], "dst": cidr, "via": via, "namespace": sv["namespace"]}
    if kind == "pod_net":
        if set(b) - {"pod", "from", "capture_s"}:
            _err(f"{where}.pod_net", f"unknown keys {sorted(set(b) - {'pod', 'from', 'capture_s'})}")
        row = pods.get(str(b.get("pod") or ""))
        if row is None or row["role"] != "server":
            _err(f"{where}.pod_net.pod", f"{b.get('pod')!r} is not a server pod of the placement table")
        if str(b.get("from") or "") != "router":
            _err(f"{where}.pod_net.from", "router: a router pod opens the connection to the pod's HTTP port across the cluster "
                                          "network, the one path the serving namespace's network policy lets in")
        _, inf = _serving(model, where)
        ri = ((inv["nodes"][row["node"]].get("rails") or {})).get(str(row["rail"])) or {}
        return {"kind": "pod_net", "node": row["node"], "pod": row["pod"], "rail": row["rail"],
                "peer": {"namespace": inf["namespace"], "selector": f"app.kubernetes.io/name={inf['router']['name']}",
                         "name": inf["router"]["name"]},
                "iface": ri.get("ifname") or row["nad"], "port": int(sv["ports"]["http"]), "namespace": sv["namespace"],
                "capture_s": int(_num(b.get("capture_s", 12), f"{where}.pod_net.capture_s"))}
    if kind == "reply_path":
        if set(b) - {"pod", "leaves"} or b.get("leaves") not in ("rail", "eth0"):
            _err(f"{where}.reply_path", "pod: the pod a pod_net action of record: reads, leaves: rail (its replies to the "
                                        "cluster network leave on its rail) or eth0")
        return {"kind": "reply_path", "pod": str(b.get("pod") or ""), "leaves": str(b["leaves"]), "namespace": sv["namespace"]}
    if kind == "mac_gone":
        if set(b) - {"pod", "wait_s"}:
            _err(f"{where}.mac_gone", "pod: the pod a pod_rail action moved, wait_s: how long the switch may keep its MAC")
        return {"kind": "mac_gone", "pod": str(b.get("pod") or ""), "wait_s": int(_num(b.get("wait_s", 660), f"{where}.mac_gone.wait_s"))}
    # placement
    if set(b) - {"pod", "rail"}:
        _err(f"{where}.placement", "pod: a pod of the table, rail: the rail its network-status annotation names")
    row = pods.get(str(b.get("pod") or ""))
    if row is None:
        _err(f"{where}.placement.pod", f"{b.get('pod')!r} is not a pod of the placement table")
    r = b.get("rail")
    if isinstance(r, bool) or not isinstance(r, int):
        _err(f"{where}.placement.rail", "a rail number")
    return {"kind": "placement", "pod": row["pod"], "rail": r, "table_rail": row["rail"], "namespace": sv["namespace"],
            "matches_table": r == row["rail"]}


def _relay_route(inv: dict, model, node: str, r, t, where: str) -> dict:
    """The rendered relay route from namespace gpu<r> on node to rail t."""
    n = _relay_node(inv, node, f"{where}.node")
    for k, v in (("rail", r), ("to_rail", t)):
        if isinstance(v, bool) or not isinstance(v, int) or str(v) not in (n.get("rails") or {}):
            _err(f"{where}.{k}", f"{v!r} is not a rail {node} holds")
    if r == t:
        _err(f"{where}.to_rail", "a relay route leads to another rail than the namespace's own")
    h = model.nodes.get(node) if model is not None else None
    ns = next((x for x in (h.relay.namespaces if h is not None and h.relay else ()) if x.rail == r), None)
    prefix = model.rails[t].prefix if model is not None and t in model.rails else None
    rt = next((x for x in (ns.routes if ns else ()) if x.dest == prefix), None)
    if ns is None or rt is None:
        _err(where, f"{node}'s namespace for rail {r} holds no rendered route to rail {t}")
    return {"node": node, "ns": ns.ns, "rail": r, "to_rail": t, "dest": rt.dest, "via": rt.via, "dev": rt.dev, "src": rt.src}


def _rail_break_action(inv: dict, model, kind: str, body, where: str) -> dict:
    """The relay's break actions and checks (chapter 5)."""
    b = body or {}
    if kind in ("relay_route", "route_src"):
        keys = {"node", "rail", "to_rail", "src"} if kind == "relay_route" else {"node", "rail", "to_rail", "pinned"}
        if set(b) - keys:
            _err(f"{where}.{kind}", f"unknown keys {sorted(set(b) - keys)}")
        rt = _relay_route(inv, model, str(b.get("node") or ""), b.get("rail"), b.get("to_rail"), f"{where}.{kind}")
        show = f"ip -n {rt['ns']} route show {rt['dest']}"
        if kind == "route_src":
            return dict(rt, kind="route_src", pinned=bool(b.get("pinned", True)), command=show)
        mode = str(b.get("src") or "")
        if mode not in ("none", "rendered"):
            _err(f"{where}.relay_route.src", "none (the route without its source pin) or rendered (with it)")
        cmd = f"ip -n {rt['ns']} route replace {rt['dest']} via {rt['via']} dev {rt['dev']}" + (f" src {rt['src']}" if mode == "rendered" else "")
        return dict(rt, kind="relay_route", mode=mode, command=cmd, show=show)
    if kind == "ns_show":
        if set(b) - {"node", "rail", "to", "get"}:
            _err(f"{where}.ns_show", f"unknown keys {sorted(set(b) - {'node', 'rail', 'to', 'get'})}")
        node = str(b.get("node") or "")
        n = _relay_node(inv, node, f"{where}.ns_show.node")
        r = b.get("rail")
        if str(r) not in (n.get("rails") or {}):
            _err(f"{where}.ns_show.rail", f"{r!r} is not a rail {node} holds")
        ns = _ns_name(n, int(r))
        lines = [f"ip -n {ns} route show"]
        get = list(b.get("get") or [])
        if get:
            to = str(b.get("to") or "")
            tn = _relay_node(inv, to, f"{where}.ns_show.to")
            for t in get:
                a = _rail_addr(tn, t) if isinstance(t, int) and not isinstance(t, bool) else None
                if not a:
                    _err(f"{where}.ns_show.get", f"{t!r} is not a rail {to} holds")
                lines.append(f"ip -n {ns} route get {a}")
        return {"kind": "ns_show", "node": node, "ns": ns, "rail": int(r), "lines": lines}
    if kind == "probe_rail":
        keys = {"id", "from", "to", "rail", "to_rail", "count", "interval_s", "timeout_s", "passes", "capture"}
        if set(b) - keys:
            _err(f"{where}.probe_rail", f"unknown keys {sorted(set(b) - keys)}")
        src, dst = str(b.get("from") or ""), str(b.get("to") or "")
        sn, dn = _relay_node(inv, src, f"{where}.probe_rail.from"), _relay_node(inv, dst, f"{where}.probe_rail.to")
        common = sorted({int(x) for x in sn["rails"]} & {int(x) for x in dn["rails"]})
        r = b.get("rail")
        if r == "all":
            if "to_rail" in b or b.get("capture"):
                _err(f"{where}.probe_rail", "rail: all pings the same rail on every rail, with no to_rail and no capture")
            pairs = [(x, x) for x in common]
        else:
            t = b.get("to_rail", r)
            if r not in common or t not in common:
                _err(f"{where}.probe_rail", f"rail and to_rail are rails both {src} and {dst} hold (have {common})")
            pairs = [(r, t)]
        rows = [_rail_row(inv, src, dst, f"r{a}-r{t}", "same" if a == t else "cross", a, t, 0) for a, t in pairs]
        for row in rows:
            row.pop("icmp_id")
        cap = None
        if b.get("capture"):
            row = rows[0]
            far = model.nodes.get(dst) if model is not None else None
            if far is None or far.relay is None:
                _err(f"{where}.probe_rail.capture", f"{dst} has no relay to capture")
            ifname = ((dn.get("rails") or {}).get(str(row["request_rail"])) or {}).get("ifname")
            cap = {"node": dst, "ifaces": [ifname, far.relay.bridge], "rail_iface": ifname, "bridge": far.relay.bridge,
                   "relay_prefix": far.relay.prefix, "src_addr": row["src_addr"], "dst_addr": row["dst_addr"]}
        return {"kind": "probe_rail", "id": str(b.get("id") or "rail"), "node": src, "to": dst, "rows": rows,
                "count": int(_num(b.get("count", 10), f"{where}.probe_rail.count")),
                "interval_s": _num(b.get("interval_s", 0.2), f"{where}.probe_rail.interval_s"),
                "timeout_s": _num(b.get("timeout_s", 1), f"{where}.probe_rail.timeout_s"),
                "passes": int(_num(b.get("passes", 1), f"{where}.probe_rail.passes")), "capture": cap}
    # far_capture
    if set(b) - {"probe", "src"} or str(b.get("src") or "") not in ("relay", "rail"):
        _err(f"{where}.far_capture", "probe: a probe_rail with capture, src: relay or rail")
    return {"kind": "far_capture", "probe": str(b.get("probe") or ""), "src": str(b["src"])}


def _fw_break_action(inv: dict, model, kind: str, body, where: str) -> dict:
    """The firewall's break actions and checks (chapter 4)."""
    b = body or {}
    fw = (inv.get("stages") or {}).get("fw")
    if kind in ("panos_api", "fw_show", "rule_order", "counter") and not fw:
        _err(where, "the lab has no firewall")
    if kind == "panos_api":
        ops = [k for k in ("del", "set", "edit") if k in b]
        if len(ops) != 1 or set(b) - {"del", "set", "edit", "rule", "destination"} or ("destination" in b) != (ops == ["edit"]):
            _err(f"{where}.panos_api", "one of del: or set: (nat or security), and rule:; or edit: security, rule: and destination:")
        op, table = ops[0], str(b[ops[0]])
        v = _fw_view(model, where)
        if table == "nat" and op != "edit":
            ent = nat_entry(v, str(b.get("rule") or ""), f"{where}.panos_api.rule")
        elif table == "security":
            ent = security_entry(v, str(b.get("rule") or ""), f"{where}.panos_api.rule")
        else:
            _err(f"{where}.panos_api.{op}", "nat or security" if op != "edit" else "security: edit changes a security rule's destination")
        if op == "edit":
            return _rule_destination(ent, fw, b["destination"], f"{where}.panos_api.destination")
        out = dict(ent, kind="panos_api", node=fw, op=op)
        if op == "del":
            out.pop("element")
        return out
    if kind == "fw_show":
        lines = [str(x) for x in b.get("lines") or []]
        if not lines or set(b) - {"lines"}:
            _err(f"{where}.fw_show", "lines: the CLI reads")
        for x in lines:
            if not x.startswith("show ") or "?" in x:
                _err(f"{where}.fw_show", f"{x!r}: show lines only, no '?'")
            if x.startswith("show log") and not re.search(r"receive_time in |start-time equal ", x):
                _err(f"{where}.fw_show", f"{x!r}: show log needs a time filter")
        return {"kind": "fw_show", "node": fw, "lines": lines}
    if kind == "probe_ping":
        extra = set(b) - {"id", "from", "to", "count", "interval_s", "timeout_s", "passes", "counters"}
        if extra:
            _err(f"{where}.probe_ping", f"unknown keys {sorted(extra)}")
        src = str(b.get("from") or "")
        sn = _node(inv, src, f"{where}.probe_ping.from")
        if sn.get("kind") not in ("vm-node", "bastion", "client"):
            _err(f"{where}.probe_ping.from", f"{src} must be a VM guest or a container with ping")
        counters = [str(x) for x in b.get("counters") or []]
        for c in counters:
            if not COUNTER_NAME.match(c):
                _err(f"{where}.probe_ping.counters", f"{c!r} is not a counter name")
        if counters and not fw:
            _err(where, "counters are the firewall's: the lab has no firewall")
        return {"kind": "probe_ping", "id": str(b.get("id") or "ping"), "node": src, "node_kind": sn.get("kind"),
                "src_addr": bare(sn.get("address")), "dst": str(b.get("to") or "public"),
                "dst_addr": _address(inv, b.get("to") or "public", f"{where}.probe_ping.to"),
                "count": int(_num(b.get("count", 5), f"{where}.probe_ping.count")),
                "interval_s": _num(b.get("interval_s", 0.5), f"{where}.probe_ping.interval_s"),
                "timeout_s": _num(b.get("timeout_s", 1), f"{where}.probe_ping.timeout_s"),
                "passes": int(_num(b.get("passes", 1), f"{where}.probe_ping.passes")), "counters": counters, "fw": fw}
    if kind == "probe_http":
        extra = set(b) - {"id", "from", "hostname", "path", "count", "interval_s", "timeout_s", "passes"}
        if extra:
            _err(f"{where}.probe_http", f"unknown keys {sorted(extra)}")
        src = str(b.get("from") or "")
        sn = _node(inv, src, f"{where}.probe_http.from")
        if sn.get("kind") != "client":
            _err(f"{where}.probe_http.from", f"{src} must be a client container (curl, the lab root CA in its bundle)")
        host = str(b.get("hostname") or "")
        dom = (inv.get("org") or {}).get("zone") or (inv.get("org") or {}).get("domain")
        if not re.match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", host) or not dom:
            _err(f"{where}.probe_http.hostname", "a single DNS label under the platform zone")
        path = str(b.get("path") or "/")
        if not path.startswith("/") or " " in path or "'" in path:
            _err(f"{where}.probe_http.path", "must start with / and hold no space or quote")
        return {"kind": "probe_http", "id": str(b.get("id") or "http"), "node": src, "client_addr": bare(sn.get("address")),
                "url": f"https://{host}.{dom}{path}", "count": int(_num(b.get("count", 10), f"{where}.probe_http.count")),
                "interval_s": _num(b.get("interval_s", 0.5), f"{where}.probe_http.interval_s"),
                "timeout_s": _num(b.get("timeout_s", 10), f"{where}.probe_http.timeout_s"),
                "passes": int(_num(b.get("passes", 1), f"{where}.probe_http.passes"))}
    if kind == "counter":
        name = str(b.get("name") or "")
        if not COUNTER_NAME.match(name) or set(b) - {"name", "probe", "rise"}:
            _err(f"{where}.counter", "name: a counter, probe: the probe_ping it is read around, rise: true or false")
        return {"kind": "counter", "node": fw, "name": name, "probe": str(b.get("probe") or ""), "rise": bool(b.get("rise", True))}
    # rule_order
    if b:
        _err(f"{where}.rule_order", "takes no settings: the running rulebase in the render's order")
    return {"kind": "rule_order", "node": fw}


def _break(inv: dict, bid: str, raw: dict, model=None) -> dict:
    where = f"breaks/{bid}.yaml"
    if not isinstance(raw, dict):
        _err(where, "must be a mapping")
    extra = set(raw) - BREAK_KEYS
    if extra:
        _err(where, f"unknown keys {sorted(extra)}")
    out = {"id": bid, "title": str(raw.get("title") or bid), "exercise": raw.get("exercise"), "note": raw.get("note")}
    for part in ("break", "record", "expect_broken", "heal", "expect_healed", "cleanup"):
        out[part] = [_break_action(inv, a, f"{where} {part}[{i}]", model) for i, a in enumerate(raw.get(part) or [])]
    if not out["break"]:
        _err(where, "break: names no action")
    if not out["heal"]:
        _err(where, "heal: names no action")
    checks = {"vlan_member", "parity", "probe_share", "counter", "rule_order", "route_src", "far_capture", "endpoints", "placement",
              "mac_gone", "key_pods", "syn_at", "tlog_rule", "cell_mode", "reply_path", "mclag_iface", "lookup_answer"}
    allowed = {"break": {"klish", "panos_api", "relay_route", "pod_rail", "pod_route", "key_hold", "key_mint", "dns_answer", "k8s_patch",
                         "dnsmasq_pin"},
               "record": {"show", "probe_tcp", "fw_show", "probe_ping", "probe_http", "ns_show", "probe_rail", "k8s_show", "pod_net",
                          "probe_gateway", "key_probe", "key_show", "probe_syn", "matrix_cells", "k8s_read", "probe_lookup"},
               "heal": {"klish", "restore", "panos_api", "relay_route", "serve", "gateway_restart", "k8s_patch"}, "expect_broken": checks,
               "expect_healed": checks, "cleanup": {"key_revoke"}}
    for part, kinds in allowed.items():
        for a in out.get(part) or []:
            if a["kind"] not in kinds:
                _err(where, f"{part}: a {a['kind']} action does not belong there (have {', '.join(sorted(kinds))})")
    probes = {a["id"]: a for a in out["record"] if a["kind"] in ("probe_tcp", "probe_ping", "probe_http", "probe_rail", "probe_gateway",
                                                                 "key_probe", "probe_syn", "matrix_cells", "probe_lookup")}
    for part in ("expect_broken", "expect_healed"):
        for a in out[part]:
            if a["kind"] in ("syn_at", "tlog_rule"):
                p = probes.get(a["probe"])
                if p is None or p["kind"] != "probe_syn":
                    _err(where, f"{part}: {a['kind']} names {a['probe']!r}, which is no probe_syn of record:")
                ids = {f"{c['node']}:{c['eth']}": c["id"] for c in p["capture"]}
                for k in ("seen", "seen_any", "unseen"):
                    for x in a.get(k) or []:
                        if x not in ids:
                            _err(where, f"{part}: syn_at {k} names {x!r}, which {a['probe']} does not capture (have {', '.join(ids)})")
                    if k in a:
                        a[k] = [ids[x] for x in a[k]]
            if a["kind"] == "cell_mode":
                p = probes.get(a["probe"])
                if p is None or p["kind"] != "matrix_cells" or a["cell"] not in p["cells"]:
                    _err(where, f"{part}: cell_mode names {a['cell']!r} of {a['probe']!r}, which no matrix_cells of record: tries")
            if a["kind"] == "lookup_answer":
                p = probes.get(a["probe"])
                if p is None or p["kind"] != "probe_lookup":
                    _err(where, f"{part}: lookup_answer names {a['probe']!r}, which is no probe_lookup of record:")
                need = a.get("tool") or {"A": "dig-a", "AAAA": "dig-aaaa"}[a["type"]]
                if need not in p["tools"]:
                    _err(where, f"{part}: lookup_answer wants {need}, which {a['probe']} does not run")
            if a["kind"] == "probe_share" and probes.get(a["probe"], {}).get("kind") in ("matrix_cells", "probe_lookup"):
                _err(where, f"{part}: probe_share names {a['probe']!r}, whose check is cell_mode or lookup_answer")
            if a["kind"] == "probe_share" and probes.get(a["probe"], {}).get("kind") == "matrix_cells":
                _err(where, f"{part}: probe_share names {a['probe']!r}, a matrix_cells: its check is cell_mode")
            if a["kind"] == "probe_share" and a["probe"] not in probes:
                _err(where, f"{part}: probe_share names {a['probe']!r}, which record: does not run")
            if a["kind"] == "probe_share" and probes[a["probe"]]["kind"] == "key_probe":
                _err(where, f"{part}: probe_share names {a['probe']!r}, a key_probe: its check is key_pods")
            if a["kind"] == "key_pods":
                p = probes.get(a["probe"])
                if p is None or p["kind"] != "key_probe":
                    _err(where, f"{part}: key_pods names {a['probe']!r}, which is no key_probe of record:")
                if a["refusing"] == "held" and not any(x["kind"] == "key_hold" for x in out["break"]):
                    _err(where, f"{part}: key_pods refusing: held, but break: holds no API gateway pod")
            if a["kind"] == "far_capture":
                p = probes.get(a["probe"])
                if p is None or p["kind"] != "probe_rail" or not p.get("capture"):
                    _err(where, f"{part}: far_capture names {a['probe']!r}, which is no probe_rail with capture: true")
            if a["kind"] == "reply_path":
                pn = next((x for x in out["record"] if x["kind"] == "pod_net" and x["pod"] == a["pod"]), None)
                if pn is None:
                    _err(where, f"{part}: reply_path names {a['pod']!r}, which no pod_net action of record: reads")
                rt = next((x for x in out["break"] if x["kind"] == "pod_route" and x["pod"] == a["pod"]), None)
                if rt is None:
                    _err(where, f"{part}: reply_path names {a['pod']!r}, which no pod_route action of break: reroutes")
                a.update({"node": pn["node"], "iface": pn["iface"], "nad": rt["nad"], "dst": rt["dst"], "via": rt["via"]})
            if a["kind"] == "mac_gone":
                mv = next((x for x in out["break"] if x["kind"] == "pod_rail" and x["pod"] == a["pod"]), None)
                if mv is None:
                    _err(where, f"{part}: mac_gone names {a['pod']!r}, which no pod_rail action of break: moves")
                a.update({"switch": mv["moved"]["switch"], "native": mv["moved"]["native"], "vlan": mv["moved"]["vlan"],
                          "mac": mv["moved"]["mac"], "node": mv["moved"]["switch"]})
            if a["kind"] == "counter":
                p = probes.get(a["probe"])
                if p is None or p["kind"] != "probe_ping" or a["name"] not in p.get("counters", []):
                    _err(where, f"{part}: counter {a['name']} names probe {a['probe']!r}, which reads no such counter")
    if not out["cleanup"]:
        # a break with no cleanup renders as it did before chapter 7 added the part
        del out["cleanup"]
    patched = {(a["resource"], a["name"]) for a in out["break"] if a["kind"] == "k8s_patch"}
    healed = {(a["resource"], a["name"]) for a in out["heal"] if a["kind"] == "k8s_patch" and a["rendered"]}
    if patched - healed:
        _err(where, "heal: puts no patched object back to its render (" + ", ".join(n for _r, n in sorted(patched - healed)) + ")")
    for a in out["break"]:
        if a["kind"] == "k8s_patch" and a["rendered"]:
            _err(where, f"break: {a['name']} as rendered changes nothing")
    moved = {a["node"] for a in out["break"] if a["kind"] in ("dns_answer", "dnsmasq_pin")}
    restored = {a["node"] for a in out["heal"] if a["kind"] == "restore" and a.get("what") == "dns"}
    if moved - restored:
        _err(where, f"heal: restore names no DNS server the break moved ({', '.join(sorted(moved - restored))})")
    if any(a["kind"] == "gateway_restart" for a in out["heal"]) and not any(a["kind"] == "key_hold" for a in out["break"]):
        _err(where, "heal: gateway_restart restarts the held pod, but break: holds none")
    minted = {a["field"] for a in out["break"] if a["kind"] == "key_mint"}
    for a in out.get("cleanup") or []:
        if a["field"] not in minted:
            _err(where, f"cleanup: key_revoke {a['field']} revokes a key break: does not mint")
    return out


def breaks(inv: dict, labdir: Path, model=None) -> dict | None:
    d = Path(labdir) / "breaks"
    files = sorted(d.glob("*.yaml")) if d.is_dir() else []
    if not files:
        return None
    from ..spec import read_yaml  # noqa: PLC0415

    out = {}
    for f in files:
        bid = f.stem
        if not re.match(r"^[0-9]+[a-z]$", bid):
            raise RenderError(f"breaks/{f.name}: a break id is the chapter number and a letter (3a)")
        out[bid] = _break(inv, bid, read_yaml(f), model)
    return {"schema": SCHEMA, "lab": inv.get("lab"), "breaks": out}


def render(model, ctx) -> dict:
    from .inventory import inventory  # noqa: PLC0415

    ch = model.meta.chapter
    raw = getattr(ch, "drills", None) if ch is not None else None
    out = {}
    inv = None
    if raw:
        inv = inventory(model)
        out["gen/drills.json"] = dumps(drills(inv, raw, model, ctx))
    labdir = getattr(ctx, "labdir", None)
    if labdir is not None and (Path(labdir) / "breaks").is_dir():
        inv = inv or inventory(model)
        b = breaks(inv, Path(labdir), model)
        if b is not None:
            out["gen/breaks.json"] = dumps(b)
    return out
