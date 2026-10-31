#!/usr/bin/env python3
"""keyprobe.py: the per-pod key probe and the key Jobs of chapter 7, as manifests, and the probe's
lines read back.

    keyprobe.py pod  --k8s gen/k8s.json --name NAME --check LABEL ROUTE FIELD EXPECT [--check ...]
                     [--repeat --max-s S --interval S]
        a Pod of the key tool (sfab/keys) in the API gateway's namespace, on the probe's own
        account (it may list the namespace's pods), with the model keys' Secret mounted read-only:
        for each check, `sfab-keys probe` sends one chat completion with the key in field FIELD
        to every Running API gateway pod by its address on ROUTE's path (the model whose route it
        is), and prints one JSON line per pod and answer; EXPECT is the status the check wants.
        With --repeat each check runs in rounds, every --interval seconds, until every pod has
        answered EXPECT or --max-s passes (a minted key loading, a revoked key leaving)
    keyprobe.py job  --k8s gen/k8s.json --name NAME (--mint|--revoke) --model M --id ID
        a Job of the key tool on the key Job's account that mints or revokes one key of the model
        keys' Secret, field <M>.<ID>; its log names the key by its fingerprint only
    keyprobe.py rows --log FILE [--label LABEL]
        the probe's lines, as JSON, one a line, from a saved log (the pod's own log)
    keyprobe.py summary --log FILE --label LABEL --expect STATUS
        per pod, the first time it answered STATUS and its last other answer: TSV pod, ip, first,
        rounds, statuses

Nothing here holds a key: the manifests name the Secret and its field, and the probe reads the
key from its own mounted file. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import sys

UID = 65532
RESOURCES = {"requests": {"cpu": "10m", "memory": "32Mi"}, "limits": {"memory": "128Mi"}}
FIELD = re.compile(r"^[a-z0-9]{1,16}\.[0-9a-f]{8}$")
NAME = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
LABEL = re.compile(r"^[a-z0-9][-a-z0-9.]*$")
KEYS_DIR = "/keys"


def inference(path: str) -> dict:
    doc = json.load(open(path, encoding="utf-8"))
    inf = doc.get("inference")
    if not inf:
        raise SystemExit("keyprobe: gen/k8s.json holds no inference block (serving off)")
    return inf


def _security(uid: int = UID) -> dict:
    return {"runAsNonRoot": True, "runAsUser": uid, "runAsGroup": uid, "fsGroup": uid, "seccompProfile": {"type": "RuntimeDefault"}}


def _restricted() -> dict:
    return {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}}


def body(model: str) -> str:
    return json.dumps({"model": model, "max_tokens": 1, "messages": [{"role": "user", "content": "Say yes."}]}, separators=(",", ":"))


def probe_command(inf: dict, label: str, route: str, field: str, expect: int, repeat: bool, max_s: float, interval: float) -> list:
    m = next((x for x in inf["models"] if x["name"] == route), None)
    if m is None:
        raise SystemExit(f"keyprobe: {route!r} is not a model the lab serves")
    g = inf["gateway"]
    cmd = ["sfab-keys", "probe", "--namespace", inf["namespace"], "--selector", f"app.kubernetes.io/name={g['name']}",
           "--port", str(g["port"]), "--path", f"{m['path']}/v1/chat/completions", "--key-file", f"{KEYS_DIR}/{field}",
           "--json", body(route), "--jsonl", "--label", label, "--expect", str(expect)]
    if repeat:
        cmd += ["--repeat", "--interval", str(interval), "--max-s", str(max_s)]
    return cmd


def pod(a) -> int:
    inf = inference(a.k8s)
    if not NAME.match(a.name):
        raise SystemExit(f"keyprobe: {a.name!r} is not a pod name")
    lines = []
    for label, route, field, expect in a.check:
        if not LABEL.match(label) or not FIELD.match(field) or not expect.isdigit():
            raise SystemExit(f"keyprobe: check {label} {route} {field} {expect}: a label, a model, a key field <model>.<id> and a status")
        lines.append(" ".join(shlex.quote(x) for x in probe_command(inf, label, route, field, int(expect), a.repeat, a.max_s, a.interval)))
    # every check runs, whatever the one before it found; the pod ends 0
    script = "\n".join(f"{x} || true" for x in lines) + "\n"
    pr = inf["probe"]
    labels = {"app.kubernetes.io/name": pr["name"], "app.kubernetes.io/part-of": "inference", "app.kubernetes.io/component": "key-probe"}
    doc = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": a.name, "namespace": inf["namespace"], "labels": labels},
           "spec": {"serviceAccountName": pr["sa"], "restartPolicy": "Never", "enableServiceLinks": False,
                    "terminationGracePeriodSeconds": 2, "securityContext": _security(),
                    "containers": [{"name": "probe", "image": inf["keys_image"], "imagePullPolicy": "IfNotPresent",
                                    "command": ["sh", "-c", script], "resources": RESOURCES, "securityContext": _restricted(),
                                    "volumeMounts": [{"name": "keys", "mountPath": KEYS_DIR, "readOnly": True}]}],
                    "volumes": [{"name": "keys", "secret": {"secretName": inf["keys"]["models"]["secret"], "defaultMode": 0o440}}]}}
    print(json.dumps(doc, sort_keys=True))
    return 0


def job(a) -> int:
    inf = inference(a.k8s)
    if not NAME.match(a.name):
        raise SystemExit(f"keyprobe: {a.name!r} is not a Job name")
    if not any(m["name"] == a.model for m in inf["models"]) or not re.match(r"^[0-9a-f]{8}$", a.id):
        raise SystemExit(f"keyprobe: {a.model}.{a.id} is not a key of a model the lab serves")
    # the key goes to the application caller that stands for the model (servekeys.caller_of)
    slug = next((c["id"] for c in inf.get("callers") or [] if c.get("kind") == "application" and a.model in (c.get("models") or [])),
                a.model)
    k = inf["keys"]["models"]
    if a.mint:
        cmd = ["sfab-keys", "mint", "--namespace", inf["namespace"], "--secret", k["secret"], "--prefix", k["prefix"],
               "--model", slug, "--id", a.id]
    else:
        cmd = ["sfab-keys", "revoke", "--namespace", inf["namespace"], "--secret", k["secret"], "--model", slug, "--id", a.id]
    lab = {"app.kubernetes.io/part-of": "inference", "app.kubernetes.io/component": "keys"}
    doc = {"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": a.name, "namespace": inf["namespace"], "labels": lab},
           "spec": {"backoffLimit": 0, "template": {"metadata": {"labels": lab}, "spec": {
               "serviceAccountName": inf["key_sa"], "restartPolicy": "Never", "enableServiceLinks": False, "securityContext": _security(),
               "containers": [{"name": "keys", "image": inf["keys_image"], "imagePullPolicy": "IfNotPresent", "command": cmd,
                               "resources": RESOURCES, "securityContext": _restricted()}]}}}}
    print(json.dumps(doc, sort_keys=True))
    return 0


def read_rows(path: str, label: str | None = None) -> list:
    out = []
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return out
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if "pod" in r and (label is None or r.get("label") == label):
            out.append(r)
    return out


def rows(a) -> int:
    for r in read_rows(a.log, a.label):
        print(json.dumps(r, sort_keys=True))
    return 0


def per_pod(rs: list, expect: int) -> dict:
    """{pod: {ip, first (the time it first answered expect, or None), rounds, statuses}}."""
    out: dict = {}
    for r in sorted(rs, key=lambda x: (x.get("t") or 0)):
        p = out.setdefault(r["pod"], {"ip": r.get("ip"), "first": None, "rounds": 0, "statuses": []})
        p["rounds"] += 1
        st = r.get("status")
        if not p["statuses"] or p["statuses"][-1] != st:
            p["statuses"].append(st)
        if st == expect and p["first"] is None:
            p["first"] = r.get("t")
    return out


def summary(a) -> int:
    pp = per_pod(read_rows(a.log, a.label), a.expect)
    for name, p in sorted(pp.items()):
        print("\t".join(str(x) for x in (name, p["ip"], p["first"] if p["first"] is not None else "-", p["rounds"],
                                           ",".join(str(s) for s in p["statuses"]))))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="keyprobe")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("pod")
    s.add_argument("--k8s", required=True)
    s.add_argument("--name", required=True)
    s.add_argument("--check", nargs=4, action="append", required=True, metavar=("LABEL", "ROUTE", "FIELD", "EXPECT"))
    s.add_argument("--repeat", action="store_true")
    s.add_argument("--max-s", type=float, default=240.0)
    s.add_argument("--interval", type=float, default=1.0)
    s = sub.add_parser("job")
    s.add_argument("--k8s", required=True)
    s.add_argument("--name", required=True)
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--mint", action="store_true")
    g.add_argument("--revoke", action="store_true")
    s.add_argument("--model", required=True)
    s.add_argument("--id", required=True)
    s = sub.add_parser("rows")
    s.add_argument("--log", required=True)
    s.add_argument("--label")
    s = sub.add_parser("summary")
    s.add_argument("--log", required=True)
    s.add_argument("--label", required=True)
    s.add_argument("--expect", type=int, required=True)
    a = ap.parse_args(argv)
    return {"pod": pod, "job": job, "rows": rows, "summary": summary}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
