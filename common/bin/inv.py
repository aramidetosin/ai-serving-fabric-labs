#!/usr/bin/env python3
"""inv: read a lab's gen/inventory.json with the standard library only.

    inv.py [--inv FILE] nodes [--role R] [--group G] [--kind K] [--clab-kind K] [--section S]
    inv.py [--inv FILE] containers [same filters]
    inv.py [--inv FILE] get PATH
    inv.py [--inv FILE] json PATH

nodes prints node names, one per line, in inventory order. containers prints their container
names. get prints a value at a dotted path (nodes.fe-sw1.mgmt): a scalar as text, a list one
item per line, a mapping as JSON. json prints the value as JSON. An empty PATH means the whole
inventory. The inventory is FILE, else $SFAB_INV, else ./gen/inventory.json. Exit status is 1
when the path does not exist, 2 on a usage or file error.
"""

import argparse
import json
import os
import sys

FILTERS = (("role", "role"), ("group", "group"), ("kind", "kind"), ("clab_kind", "clab-kind"), ("section", "section"))


def load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError) as e:
        print(f"inv: cannot read {path}: {e}", file=sys.stderr)
        sys.exit(2)


def lookup(data, path):
    cur = data
    if not path:
        return True, cur
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return False, None
    return True, cur


def selected(data, args):
    order = data.get("order") or list((data.get("nodes") or {}).keys())
    nodes = data.get("nodes") or {}
    out = []
    for name in order:
        n = nodes.get(name, {})
        if all(getattr(args, attr) is None or n.get(attr) == getattr(args, attr) for attr, _ in FILTERS):
            out.append(name)
    return out


def emit(value):
    if isinstance(value, dict):
        print(json.dumps(value, indent=2, sort_keys=True))
    elif isinstance(value, list):
        for v in value:
            print(json.dumps(v, sort_keys=True) if isinstance(v, (dict, list)) else ("" if v is None else v))
    elif isinstance(value, bool):
        print("true" if value else "false")
    elif value is not None:
        print(value)


def main(argv=None):
    p = argparse.ArgumentParser(prog="inv", description="read gen/inventory.json")
    p.add_argument("--inv", default=os.environ.get("SFAB_INV") or os.path.join("gen", "inventory.json"))
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("nodes", "containers"):
        sp = sub.add_parser(name)
        for attr, flag in FILTERS:
            sp.add_argument(f"--{flag}", dest=attr)
    for name in ("get", "json"):
        sp = sub.add_parser(name)
        sp.add_argument("path", nargs="?", default="")
    a = p.parse_args(argv)
    data = load(a.inv)
    if a.cmd in ("nodes", "containers"):
        names = selected(data, a)
        for n in names:
            print(data["nodes"][n]["container"] if a.cmd == "containers" else n)
        return 0
    ok, value = lookup(data, a.path)
    if not ok:
        print(f"inv: no {a.path!r} in {a.inv}", file=sys.stderr)
        return 1
    if a.cmd == "json":
        print(json.dumps(value, indent=2, sort_keys=True))
    else:
        emit(value)
    return 0


if __name__ == "__main__":
    sys.exit(main())
