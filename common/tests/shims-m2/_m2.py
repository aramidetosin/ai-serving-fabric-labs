#!/usr/bin/env python3
"""Stand-ins for ssh and docker in a healthy sfab-m2, for common/tests/test_m2.py.

They answer what the M2 harness adds and hand everything else to the shared stand-ins
(common/tests/shims/): a planned command is answered from m2_world.healthy() by its slug; the
finish stage's and the audit's own kubectl calls from the same world; node-sync's guest file
reads and writes from a file store ($SHIM_GUEST_FS). Every call is logged to $SHIM_LOG.
$SHIM_M2_FAULT names one m2_world fault to show.
"""
import hashlib
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SHARED = HERE.parent / "shims"
sys.path.insert(0, str(HERE.parent))
import m2_world  # noqa: E402

INV = json.load(open(os.environ["SHIM_INV"]))
RENDER = Path(os.environ["SHIM_RENDER"])
NODES = INV["nodes"]
BY_IP = {n["mgmt"]: name for name, n in NODES.items()}
PREFIX = INV["prefix"]
_WORLD = None


def world():
    global _WORLD
    if _WORLD is None:
        _WORLD = m2_world.healthy(INV, RENDER)
        if os.environ.get("SHIM_M2_FAULT"):
            _WORLD = m2_world.break_world(_WORLD, os.environ["SHIM_M2_FAULT"])
    return _WORLD


def log(tool, argv):
    with open(os.environ["SHIM_LOG"], "a") as f:
        f.write(json.dumps([tool + "-m2"] + argv) + "\n")


def planned(node, command):
    """The healthy text of a command NODE's plan names, or None."""
    import judge
    for row in judge.plan(INV, node):
        if row["command"].strip() == command.strip():
            return (world().get(node) or {}).get(row["slug"])
    return None


def unquote_bash_c(remote: str):
    """'sudo bash -c <%q-quoted script>' (H), or 'sudo setsid bash -c <script> </dev/null >/dev/null
    2>&1 &' (HBG) -> the script (bash undoes printf %q, $'...' included)."""
    idx = 3
    if remote.startswith("sudo setsid bash -c "):
        remote, idx = remote.split(" </dev/null", 1)[0], 4
    r = subprocess.run(["bash", "-c", f'eval "a=($1)"; printf %s "${{a[{idx}]}}"', "_", remote], capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else None


# ---------------------------------------------------------------------------- the cluster, as kubectl

KNODE = (INV.get("stages") or {}).get("kubectl")


def remote_words(remote: str):
    """The remote command line as bash would split it (printf %q undone), or None."""
    r = subprocess.run(["bash", "-c", 'eval "a=($1)"; printf "%s\\0" "${a[@]}"', "_", remote], capture_output=True, text=True)
    return r.stdout.split("\0")[:-1] if r.returncode == 0 else None


def kube_remote(remote: str):
    """lib.sh K/KI (sudo env KUBECONFIG=... kubectl ARGS) or KSH/KSHI (sudo env KUBECONFIG=... PATH=...
    bash -c SCRIPT) on the init node -> kube()'s answer, or None for any other command."""
    if not remote.startswith("sudo env KUBECONFIG="):
        return None
    w = remote_words(remote)
    if not w:
        return None
    w = w[2:]
    while w and "=" in w[0] and not w[0].startswith("-"):
        w = w[1:]
    if w[:1] == ["kubectl"]:
        return kube(w[1:])
    if w[:2] == ["bash", "-c"] and len(w) > 2:
        return kube([], w[2])
    return None


def kube(args: list, script: str | None = None):
    """kubectl with the admin kubeconfig on the init node: argv (K) or a shell script (KSH). Returns
    the text, or None."""
    w = world().get(KNODE) or {}
    if script is not None:
        s = script.strip()
        if "get cm cilium-config" in s and "@@" in s:
            pods = json.loads(w["pods"])
            agents = [p for p in pods["items"] if (p["metadata"].get("labels") or {}).get("k8s-app") == "cilium"]
            return w["cilium_config"] + "\n@@\n" + json.dumps({"items": agents})
        if "kubectl get nodes -o json" in s and "@@" in s:
            return w["nodes"] + "\n@@\n" + w["pods"]
        if s.startswith("helm -n kube-system get metadata cilium"):
            return json.dumps({"name": "cilium", "namespace": "kube-system", "version": "1.19.7"})
        p = planned(KNODE, s)
        if p is not None:
            return p
        if s.startswith("helm upgrade") or s.startswith("helm -n") or "apply -f -" in s:
            return "Release installed" if s.startswith("helm") else "applied"
        return None
    a = " ".join(args)
    if a.startswith("get nodes -o json"):
        return w["nodes"]
    if a.startswith("get events -A --field-selector type=Warning -o json"):
        return w["events_warning"]
    if a.startswith("get events -A --field-selector type=Warning -o custom-columns"):
        return ""
    if a.startswith("get events -A --field-selector type=Warning -o jsonpath="):
        return "\n".join(sorted({e["metadata"]["namespace"] for e in json.loads(w["events_warning"])["items"]}))
    if args[:1] == ["-n"] and args[2:6] == ["get", "events", "--field-selector", "type=Warning"]:
        items = [e for e in json.loads(w["events_warning"])["items"] if e["metadata"]["namespace"] == args[1]]
        return json.dumps({"items": items}) if "json" in args else "\n".join(e["metadata"]["name"] for e in items)
    if args[:1] == ["-n"] and args[2:4] == ["delete", "events"]:
        return "ok"
    if a.startswith("delete events") or a.startswith("apply ") or " rollout " in f" {a} " or a.startswith("delete namespace") \
            or a.startswith("create namespace"):
        return "ok"
    if a.startswith("get leases -A -o json") or a.startswith("-n kube-system get leases"):
        return w["leases"]
    if a.endswith("-o jsonpath={.status.phase}"):
        return "Succeeded"
    if " logs vol-" in f" {a}":
        blob = hashlib.sha256(args[-1].rsplit("-", 1)[0].encode()).hexdigest()
        return f"written {blob}  /data/blob" if args[-1].endswith("-write") else f"read {blob}  /data/blob"
    if " get pvc " in f" {a} ":
        claim = args[args.index("pvc") + 1]
        return f"NAME STATUS VOLUME CAPACITY ACCESS MODES STORAGECLASS AGE\n{claim} Bound pvc-1 1Gi RWO x 1m"
    return None


# ---------------------------------------------------------------------------- the trace in a guest

def guest_trace(node, script):
    """tcpdump in a guest, as trace.sh drives it: started in the background, found, stopped, decoded
    in the guest and read back. Returns the output, or False for a command that fails (pgrep after
    the stop)."""
    import re
    import base64
    sys.path.insert(0, str(HERE))
    import _trace
    st = Path(os.environ["SHIM_STATE"]).with_suffix(".trace.json")
    try:
        d = json.load(open(st))
    except (OSError, ValueError):
        d = {}
    m = re.search(r"sfab-trace-([A-Za-z0-9_.-]+?)\.(pcap|txt)", script)
    pid = m.group(1) if m else ""
    key = f"{node}:{pid}"
    out = ""
    if "exec timeout" in script and " tcpdump " in script:
        d[key] = "running"
    elif script.startswith("test -f"):
        out = None if d.get(key) else False
        out = "" if out is None else out
    elif script.startswith("pkill"):
        d[key] = "stopped"
    elif script.startswith("pgrep"):
        out = "" if d.get(key) == "running" else False
    elif script.startswith("tcpdump -nn") and " -r " in script:
        out = "1"
    elif script.startswith("cat "):
        out = _trace.decode_for(pid)
    elif script.startswith("base64"):
        out = base64.b64encode(b"\xd4\xc3\xb2\xa1guest\n").decode()
    json.dump(d, open(st, "w"))
    return out


# ---------------------------------------------------------------------------- node-sync's guest files

def fs_path(node):
    d = os.environ.get("SHIM_GUEST_FS")
    return Path(d) / f"{node}.json" if d else None


def fs_load(node):
    """The guest's files, {path: {content, mode, owner}}, kept in $SHIM_GUEST_FS/<node>.json (one file
    per guest: node-sync works on the guests in parallel), or None when there is no store."""
    p = fs_path(node)
    if p is None:
        return None
    try:
        return json.load(open(p))
    except (OSError, ValueError):
        return {}


def fs_save(node, d):
    json.dump(d, open(fs_path(node), "w"), indent=1, sort_keys=True)


def guest_fs(node, script):
    files = fs_load(node)
    if files is None:
        return None
    if "sfab_nodesync_inventory" in script:
        paths = shlex.split(script.rsplit("sfab_nodesync_inventory ", 1)[1])
        out = []
        for p in paths:
            f = files.get(p)
            if f is None:
                out.append(f"MISSING - - {p}")
            else:
                out.append(f"{hashlib.sha256(f['content'].encode()).hexdigest()} {f['mode']} {f['owner']} {p}")
        if "/etc/sfab/node.env" in files:
            srt = "".join(l + "\n" for l in sorted(files["/etc/sfab/node.env"]["content"].splitlines(), key=lambda x: x.encode()))
            out.append(f"SORTED {hashlib.sha256(srt.encode()).hexdigest()} - /etc/sfab/node.env")
        return "\n".join(out)
    if "sfab_nodesync_install" in script:
        p, mode, owner = shlex.split(script.rsplit("sfab_nodesync_install ", 1)[1])[:3]
        files[p] = {"content": sys.stdin.read(), "mode": mode.lstrip("0") or "0", "owner": owner}
        fs_save(node, files)
        return ""
    if script.startswith("cat /etc/sfab/node.env"):
        return (files.get("/etc/sfab/node.env") or {}).get("content", "")
    if script in ("systemctl daemon-reload", "systemctl try-restart lldpd.service", "networkctl reload", "/opt/sfab/bin/netsetup.sh"):
        files.setdefault("_applied", []).append(script)
        fs_save(node, files)
        return ""
    return None


# ---------------------------------------------------------------------------- the tools

def ssh(argv):
    log("ssh", argv)
    i, target = 0, None
    while i < len(argv):
        a = argv[i]
        if a in ("-o", "-i", "-p", "-l"):
            i += 2
            continue
        if a.startswith("-"):
            i += 1
            continue
        target = a
        break
    host = target.split("@", 1)[1] if target and "@" in target else None
    node = BY_IP.get(host)
    remote = " ".join(argv[i + 1:])
    if node and node in (os.environ.get("SHIM_SSH_DOWN") or "").split():
        print(f"ssh: connect to host {host} port 22: Connection timed out", file=sys.stderr)
        return 255
    if node and node == KNODE and remote.startswith("sudo env KUBECONFIG="):
        if "-n" not in argv[:i]:
            sys.stdin.read()          # KI and KSHI: the manifest on standard input
        out = kube_remote(remote)
        if out is not None:
            if out:
                print(out)
            return 0
    if node and NODES[node]["kind"] == "vm-node" and remote.startswith(("sudo bash -c ", "sudo setsid bash -c ")):
        script = unquote_bash_c(remote)
        if script is not None and "tar -C " in script and " -xf -" in script:
            sys.stdin.read()              # finish's copy_in: bootstrap/k8s as a tar stream
            return 0
        if script is not None and script.startswith("kubeadm kubeconfig user ") and node == KNODE:
            # finish's operators step: a kubeconfig with a stand-in client certificate (no key material)
            user = script.split("--client-name ", 1)[1].split()[0]
            print(f"apiVersion: v1\nkind: Config\nclusters:\n- cluster:\n    server: https://{INV['k8s']['api_fqdn']}:6443\n"
                  f"  name: {INV['lab']}\nusers:\n- name: {user}\n  user:\n    client-certificate-data: c3RhbmQtaW4=\n")
            return 0
        if script is not None:
            out = guest_fs(node, script)
            if out is None:
                out = planned(node, script)
            if out is None and script.startswith("systemctl show") and "sfab-cluster.service" in script:
                out = world()[node]["cluster_unit"]
            if out is None and script.startswith("journalctl"):
                out = "cluster-bootstrap: done"
            # the audit's NVMe/TCP probe, while its claim is bound (TrueNAS listens only then)
            if out is None and script.startswith("timeout 5 bash -c '</dev/tcp/"):
                if os.environ.get("SHIM_M2_FAULT") == "nvme-closed" and node == "k8s-gpu2":
                    print("bash: connect: Connection refused", file=sys.stderr)
                    return 1
                # the storage data VLAN is Layer 2 only: open from a node with a unit in it alone
                if "/4420'" in script and (world().get(node) or {}).get("storage_ports") != "2049 open":
                    print("bash: connect: Network is unreachable", file=sys.stderr)
                    return 1
                out = ""
            if out is None and "sfab-trace-" in script:
                out = guest_trace(node, script)
                if out is False:
                    return 1
            if out is not None:
                if out:
                    print(out)
                return 0
    os.execv(sys.executable, [sys.executable, str(SHARED / "_devices.py"), "ssh"] + argv)


def docker(argv):
    sub = argv[0] if argv else ""
    if sub == "exec":
        rest = argv[1:]
        while rest and rest[0].startswith("-"):
            rest = rest[2:] if rest[0] in ("-e", "-u", "-w") else rest[1:]
        ctr, cmd = rest[0], rest[1:]
        node = ctr[len(PREFIX):] if ctr.startswith(PREFIX) else None
        out = None
        if node and cmd[:2] == ["sh", "-c"]:
            out = planned(node, cmd[2])
        elif node and cmd[:2] == ["vtysh", "-c"]:
            out = planned(node, cmd[2])
        elif node and cmd[:1] == ["dig"] and os.environ.get("SHIM_TRACE_HOLDER"):
            out = INV["gateways"]["gw-users"]["vip"]
        elif node and cmd[:1] == ["curl"] and os.environ.get("SHIM_TRACE_HOLDER"):
            out = "HTTP/2 200 \nserver: envoy\n\nsfab-m2-trace"
        if out is not None:
            log("docker", argv)
            if out:
                print(out)
            return 0
    if sub == "logs":
        ctr = argv[-1]
        node = ctr[len(PREFIX):] if ctr.startswith(PREFIX) else None
        if node == "inet-registry":
            log("docker", argv)
            print(world()["inet-registry"]["access_log"])
            return 0
        if node == "bastion":
            log("docker", argv)
            print(world()["bastion"]["init_log"])
            return 0
    if sub == "inspect" and "-f" in argv and "RestartCount" in argv[argv.index("-f") + 1]:
        log("docker", argv)
        print("running healthy restarts=0 started=2026-10-20T09:00:00Z")
        return 0
    os.execv(sys.executable, [sys.executable, str(SHARED / "_shim.py"), "docker"] + argv)


TLOG = """
Time                App             From            Src Port   Source
Rule                Action          To              Dst Port   Destination
                    Src User        Dst User                   End Reason
Rule_UUid
====================================================================================================
2026/10/20 10:00:05 ssl             enterprise      41443      10.24.10.10
staff-to-users-gate allow           ingress         443        10.20.11.210
                                                               tcp-fin
3f0a5f6e-0000-4000-8000-000000000001"""


def sshpass(argv):
    data = sys.stdin.read()
    if "show log traffic" in data:
        log("sshpass", argv)
        for line in data.splitlines():
            print(f"admin@fw> {line}")
            if line.startswith("show log traffic"):
                print(TLOG)
            if line == "exit":
                break
        return 0
    r = subprocess.run([sys.executable, str(SHARED / "_devices.py"), "sshpass"] + argv, input=data, text=True)
    return r.returncode


def nsenter(argv):
    """The shared stand-in, except that a container host's out-of-band link carries the MAC the
    shared switch stand-in shows on that host's access port (a container's veth MAC is what a
    switch learns from it, and the audit sets every collected container veth MAC aside)."""
    pid = int(argv[argv.index("-t") + 1])
    cmd = argv[argv.index("-n") + 1:]
    if cmd[:1] == ["timeout"]:
        cmd = cmd[2:]
    if cmd[:1] == ["tcpdump"]:
        os.execv(sys.executable, [sys.executable, str(HERE / "_trace.py")] + cmd[1:])
    if cmd[:1] == ["curl"] and any("/v2/_catalog" in a for a in cmd):
        # collect.sh host_registry_catalog: the registry's catalog over HTTPS in its own namespace
        log("nsenter", argv)
        print(world()["inet-registry"]["catalog"])
        return 0
    r = subprocess.run([sys.executable, str(SHARED / "_shim.py"), "nsenter"] + argv, capture_output=True, text=True)
    out = r.stdout
    if cmd[:4] == ["ip", "-j", "link", "show"] or cmd[:5] == ["ip", "-d", "-j", "link", "show"]:
        state = json.load(open(os.environ["SHIM_STATE"]))
        name = next((n for n, c in (state.get("containers") or {}).items() if c.get("pid") == pid), "")
        node = name[len(PREFIX):] if name.startswith(PREFIX) else None
        oob = ((NODES.get(node) or {}).get("oob") or {}).get("eth") if node and NODES.get(node, {}).get("kind") != "vm-node" else None
        if oob:
            links = json.loads(out or "[]")
            for l in links:
                if l.get("ifname") == oob:
                    l["address"] = "0c:00:aa:bb:cc:03"
            out = json.dumps(links) + "\n"
    sys.stdout.write(out)
    sys.stderr.write(r.stderr)
    return r.returncode


if __name__ == "__main__":
    sys.path.insert(0, str(HERE.parents[1] / "audit"))
    tool = sys.argv[1]
    sys.exit({"ssh": ssh, "docker": docker, "nsenter": nsenter, "sshpass": sshpass}[tool](sys.argv[2:]))
