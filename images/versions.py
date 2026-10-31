#!/usr/bin/env python3
"""Print a pin from spec/versions.yaml for images/Makefile.

    versions.py get kubernetes.version          v1.35.8
    versions.py get guest.ubuntu_cloud_image.serial
    versions.py image ubuntu_base               ubuntu:24.04@sha256:0081...
    versions.py image client                    sfab/client:2

`get` prints a scalar (nothing for null) and fails on a mapping or a missing key. `image` prints
an image's ref, with @<digest> appended when versions.yaml records one.

PyYAML is used when it is installed. Without it a small reader handles the subset versions.yaml
is written in: block mappings by indentation, one-line flow mappings, plain and quoted scalars,
comments. The tests check that both readers agree on the real file.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

VERSIONS = Path(__file__).resolve().parent.parent / "spec" / "versions.yaml"


class PinError(Exception):
    pass


def _scalar(s: str):
    s = s.strip()
    if s in ("", "~", "null", "Null", "NULL"):
        return None
    if s in ("true", "True", "TRUE"):
        return True
    if s in ("false", "False", "FALSE"):
        return False
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        return s[1:-1]
    if re.fullmatch(r"[-+]?[0-9]+", s):
        return int(s)
    if re.fullmatch(r"[-+]?([0-9]+\.[0-9]*|\.[0-9]+)", s):
        return float(s)
    return s


def _strip_comment(line: str) -> str:
    out, quote = [], None
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
            break
        out.append(ch)
    return "".join(out).rstrip()


def _split_flow(body: str) -> list[str]:
    parts, depth, quote, cur = [], 0, None, []
    for ch in body:
        if quote:
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch in "{[":
            depth += 1
        elif ch in "}]":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
            continue
        cur.append(ch)
    if "".join(cur).strip():
        parts.append("".join(cur))
    return parts


def _value(s: str):
    s = s.strip()
    if s.startswith("{") and s.endswith("}"):
        out = {}
        for part in _split_flow(s[1:-1]):
            k, sep, v = part.partition(":")
            if not sep:
                raise PinError(f"flow mapping entry without a colon: {part!r}")
            out[_scalar(k)] = _value(v)
        return out
    if s.startswith("[") and s.endswith("]"):
        return [_value(p) for p in _split_flow(s[1:-1])]
    return _scalar(s)


def mini_load(text: str) -> dict:
    """Block mappings by indentation, with flow mappings and scalars as values."""
    root: dict = {}
    stack = [(-1, root)]
    bare = []  # (parent, key) of keys written with nothing after the colon
    for n, raw in enumerate(text.splitlines(), 1):
        line = _strip_comment(raw)
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        body = line.strip()
        if body.startswith("- "):
            raise PinError(f"line {n}: block lists are not supported by the small reader")
        key, sep, rest = body.partition(":")
        if not sep:
            raise PinError(f"line {n}: expected 'key: value'")
        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]
        k = _scalar(key)
        if rest.strip():
            parent[k] = _value(rest)
        else:
            parent[k] = {}
            bare.append((parent, k))
            stack.append((indent, parent[k]))
    # A key with nothing below it is null, as in YAML, not an empty mapping.
    for parent, k in reversed(bare):
        if parent[k] == {}:
            parent[k] = None
    return root


def load(path: Path = VERSIONS) -> dict:
    text = path.read_text(encoding="utf-8")
    try:
        import yaml  # noqa: PLC0415
    except ImportError:
        return mini_load(text)
    return yaml.safe_load(text)


def get(tree: dict, dotted: str):
    cur = tree
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            raise PinError(f"{dotted}: no such key in spec/versions.yaml")
        cur = cur[part]
    return cur


def image(tree: dict, key: str) -> str:
    entry = get(tree, f"images.{key}")
    if not isinstance(entry, dict) or not entry.get("ref"):
        raise PinError(f"images.{key} has no ref")
    ref, digest = str(entry["ref"]), entry.get("digest")
    return f"{ref}@{digest}" if digest else ref


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[0] not in ("get", "image"):
        print(__doc__.strip().splitlines()[0], file=sys.stderr)
        print("usage: versions.py get <dotted.key> | image <key>", file=sys.stderr)
        return 2
    try:
        tree = load()
        if argv[0] == "image":
            print(image(tree, argv[1]))
            return 0
        v = get(tree, argv[1])
    except (OSError, PinError) as e:
        print(f"versions.py: {e}", file=sys.stderr)
        return 1
    if isinstance(v, (dict, list)):
        print(f"versions.py: {argv[1]} is not a scalar", file=sys.stderr)
        return 1
    print("" if v is None else (str(v).lower() if isinstance(v, bool) else v))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
