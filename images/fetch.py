#!/usr/bin/env python3
"""fetch.py: put a pinned file in the vendor directory, checked against its sha256.

    fetch.py <dotted pin> <directory> [--name FILE]

The pin is a mapping in spec/versions.yaml with url and sha256 (serving.llama_cpp,
serving.models.chat, serving.debs.libssl3, keys.pyyaml, ...); its file (or asset) names the file, and
size, when given, is checked too. A copy already in the directory is used when its sha256
matches, and nothing is downloaded. Otherwise the file is downloaded from url into <name>.part,
checked, and moved into place; a download whose sha256 or size differs is removed and refused.
It prints one line saying which it did. Standard library only.
"""

from __future__ import annotations

import hashlib
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import versions as pins  # noqa: E402  (images/versions.py)


class FetchError(Exception):
    pass


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def pin_of(tree: dict, dotted: str) -> dict:
    p = pins.get(tree, dotted)
    if not isinstance(p, dict):
        raise FetchError(f"{dotted} is not a mapping in spec/versions.yaml")
    name = p.get("file") or p.get("asset")
    if not name or "/" in str(name) or not p.get("url") or not p.get("sha256"):
        raise FetchError(f"{dotted} needs file (or asset), url and sha256")
    if len(str(p["sha256"])) != 64:
        raise FetchError(f"{dotted}.sha256 is not 64 hex digits")
    return {"name": str(name), "url": str(p["url"]), "sha256": str(p["sha256"]), "size": p.get("size")}


def download(url: str, dest: Path, opener=None) -> None:
    op = opener or (lambda req: urllib.request.urlopen(req, timeout=600))
    req = urllib.request.Request(url, headers={"User-Agent": "sfab-fetch/1"})
    with op(req) as r, open(dest, "wb") as f:
        for chunk in iter(lambda: r.read(1 << 20), b""):
            f.write(chunk)


def fetch(pin: dict, directory: Path, name: str | None = None, opener=None) -> str:
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / (name or pin["name"])
    if target.is_file():
        have = sha256_file(target)
        if have == pin["sha256"]:
            return f"[fetch] {target} is the pinned file; nothing to download"
        print(f"[fetch] {target} has sha256 {have}, not the pin; downloading it again", flush=True)
    part = target.with_name(target.name + ".part")
    print(f"[fetch] downloading {pin['url']}", flush=True)
    try:
        download(pin["url"], part, opener)
        have = sha256_file(part)
        if have != pin["sha256"]:
            raise FetchError(f"the download has sha256 {have}, the pin says {pin['sha256']}")
        if pin.get("size") is not None and part.stat().st_size != int(pin["size"]):
            raise FetchError(f"the download is {part.stat().st_size} bytes, the pin says {pin['size']}")
    except BaseException:
        part.unlink(missing_ok=True)
        raise
    part.replace(target)
    return f"[fetch] {target}: downloaded and checked (sha256 {pin['sha256'][:12]})"


def main(argv: list) -> int:
    args = list(argv)
    name = None
    if "--name" in args:
        i = args.index("--name")
        name = args[i + 1] if i + 1 < len(args) else None
        del args[i:i + 2]
    if len(args) != 2 or (name is not None and ("/" in name or not name)):
        print(__doc__.strip().splitlines()[0], file=sys.stderr)
        print("usage: fetch.py <dotted pin> <directory> [--name FILE]", file=sys.stderr)
        return 2
    try:
        print(fetch(pin_of(pins.load(), args[0]), Path(args[1]), name))
        return 0
    except (FetchError, pins.PinError, OSError) as e:
        print(f"fetch.py: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
