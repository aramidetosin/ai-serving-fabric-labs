#!/usr/bin/env python3
"""Stand-ins for docker, containerlab and nsenter in common/tests/test_stages.py.

They keep their world in the JSON file $SHIM_STATE and append every call to $SHIM_LOG, so a
test can assert what a stage script did. They model only what the stage scripts ask of them.
"""
import json
import os
import sys

STATE, LOG = os.environ["SHIM_STATE"], os.environ["SHIM_LOG"]


def load():
    try:
        return json.load(open(STATE))
    except (OSError, ValueError):
        return {}


def save(s):
    json.dump(s, open(STATE, "w"), indent=1, sort_keys=True)


def log(tool, argv):
    with open(LOG, "a") as f:
        f.write(json.dumps([tool] + argv) + "\n")


def fmt(f, name, c):
    table = {
        "{{.Names}}": name,
        "{{.State.StartedAt}} {{.State.Running}}": f"{c.get('started', 'x')} {'true' if c.get('running') else 'false'}",
        "{{.State.Running}}": "true" if c.get("running") else "false",
        "{{.State.Pid}}": str(c.get("pid", 0) if c.get("running") else 0),
        "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}": c.get("health", "none"),
        "{{json .Config}}": json.dumps({"Cmd": c.get("cmd", []), "Env": c.get("env", [])}),
        "{{json .Config.Env}}": json.dumps(c.get("env", [])),
        "{{.Name}}": "/" + name,
    }
    return table.get(f, "?")


def docker(argv):
    s = load()
    cs = s.setdefault("containers", {})
    sub, rest = argv[0], argv[1:]
    if sub == "version":
        print("27.0.0")
        return 0
    if sub == "info":
        # Docker's data root: the world's docker_root, else the directory the world lives in.
        print(s.get("docker_root") or os.path.dirname(os.path.abspath(STATE)))
        return 0
    if sub == "ps":
        for n in sorted(cs):
            if "-a" in rest or cs[n].get("running"):
                print(n)
        return 0
    if sub == "inspect":
        f, names, i = None, [], 0
        while i < len(rest):
            if rest[i] in ("-f", "--format"):
                f = rest[i + 1]
                i += 2
                continue
            names.append(rest[i])
            i += 1
        rc = 0
        for n in names:
            if n not in cs:
                print(f"Error: No such object: {n}", file=sys.stderr)
                rc = 1
                continue
            print(fmt(f, n, cs[n]))
        return rc
    if sub == "rm":
        for n in [a for a in rest if not a.startswith("-")]:
            cs.pop(n, None)
        save(s)
        return 0
    if sub == "stop":
        for n in [a for a in rest if not a.startswith("-") and not a.isdigit()]:
            if n in cs:
                cs[n]["running"] = False
        save(s)
        return 0
    if sub == "update":
        return 0
    if sub == "logs":
        name = rest[-1]
        logs = (s.get("logs") or {}).get(name)
        if logs is None:
            logs = "INFO KLISH startup config applied\nINFO Startup complete in: 0:02:52" if "sw" in name else \
                   "INFO XML startup config commit finished: result=OK"
        print(logs)
        return 0
    if sub == "exec":
        if "test" in rest:
            return 1
        if rest[-2:] == ["cat", "/config/startup-config.cfg"] and os.environ.get("SHIM_FW_XML"):
            sys.stdout.write(open(os.environ["SHIM_FW_XML"]).read())
        return 0
    if sub == "image":
        ref = rest[-1]
        img = (s.get("images") or {}).get(ref)
        if not img:
            return 1
        f = rest[rest.index("--format") + 1] if "--format" in rest else "{{.Id}}"
        print(json.dumps([ref + "@sha256:00"]) if "RepoDigests" in f else img)
        return 0
    if sub == "network":
        nets = s.get("networks") or []
        if rest[0] == "ls":
            for n in nets:
                print(n["Name"])
            return 0
        if rest[0] == "inspect":
            print(json.dumps([n for n in nets if n["Name"] in rest[1:]]))
            return 0
    if sub == "cp":
        return 0
    print(f"docker shim: unhandled {argv}", file=sys.stderr)
    return 2


def containerlab(argv):
    s = load()
    cs = s.setdefault("containers", {})
    if argv[:1] == ["version"]:
        # The release on the lab host (spec/versions.yaml tools.containerlab); a test sets
        # SHIM_CLAB_VERSION to stand in for a host on another release.
        print(f"    version: {os.environ.get('SHIM_CLAB_VERSION', '0.82.0')}")
        return 0
    if argv[:1] == ["inspect"]:
        print(json.dumps(s.get("clab") or {}))
        return 0
    topo = argv[argv.index("-t") + 1] if "-t" in argv else ""
    lab = ""
    for line in open(topo):
        if line.startswith("name:"):
            lab = line.split(":", 1)[1].strip()
    if argv[0] == "deploy":
        for i, n in enumerate(os.environ.get("SHIM_NODES", "").split()):
            cs[f"{lab}-{n}"] = {"running": True, "started": f"2026-10-14T10:00:{i:02d}Z", "pid": 5000 + i,
                                "health": "healthy", "env": ["NUM_NICS=8"], "cmd": ["--password", "shimpw"]}
        save(s)
        return 0
    if argv[0] == "destroy":
        # containerlab prints the output of a lab container that exited (a launcher's log, which
        # may list its environment); a test sets SHIM_CLAB_EXITED_OUTPUT to that output
        if os.environ.get("SHIM_CLAB_EXITED_OUTPUT"):
            print(f'10:00:00 ERRO container "{lab}-truenas1" exited; container output:', file=sys.stderr)
            print(os.environ["SHIM_CLAB_EXITED_OUTPUT"], file=sys.stderr)
        for n in list(cs):
            if n.startswith(lab + "-"):
                del cs[n]
        save(s)
        return 0
    return 2


def nsenter(argv):
    s = load()
    pid = int(argv[argv.index("-t") + 1])
    cmd = argv[argv.index("-n") + 1:]
    eths = []
    for c in (s.get("containers") or {}).values():
        if c.get("pid") == pid and c.get("running"):
            eths = c.get("eths") or [f"eth{i}" for i in range(1, 14)]
    down = set(s.get("down_links") or [])
    if cmd[:4] == ["ip", "-j", "link", "show"] or cmd[:5] == ["ip", "-d", "-j", "link", "show"]:
        print(json.dumps([{"ifname": e, "address": f"aa:c1:ab:{pid % 256:02x}:00:{i:02x}"} for i, e in enumerate(eths, 1)]))
        return 0
    if cmd[:2] == ["ethtool", "-k"]:
        print("tx-checksumming: off\ngeneric-receive-offload: off\nrx-gro-hw: off [fixed]\nlarge-receive-offload: off [fixed]")
        return 0
    if cmd[:1] == ["cat"] and "disable_ipv6" in cmd[-1]:
        print("1")
        return 0
    if cmd[:4] == ["ip", "-o", "link", "show"]:
        for i, e in enumerate(eths, 2):
            flags = "BROADCAST,MULTICAST" if f"{pid}:{e}" in down else "BROADCAST,MULTICAST,UP,LOWER_UP"
            print(f"{i}: {e}@if{100 + i}: <{flags}> mtu 9500 qdisc noqueue state UP")
        return 0
    return 0


if __name__ == "__main__":
    tool, args = sys.argv[1], sys.argv[2:]
    log(tool, args)
    sys.exit({"docker": docker, "containerlab": containerlab, "nsenter": nsenter}[tool](args))
