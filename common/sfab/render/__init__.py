"""The renderer registry, and writing a lab's outputs with gen/RENDER.json.

A renderer is a module sfab.render.<name> with one function:

    render(model, ctx) -> dict[str, str | bytes]

mapping a path relative to the lab's output directory (posix form, under topo.clab.yml,
bootstrap/ or gen/) to the file's content. Renderers never write files themselves and never
read the clock; render_all() merges their outputs, and write_outputs() writes them. A renderer
module that is not present yet is skipped with a warning, so the generator works while the
renderers are written.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

# Run order. inventory runs last; RENDER.json is computed after every renderer.
RENDERERS = ("clab", "klish", "expect", "panos", "host", "frr", "storage", "dns", "ca", "k8s", "trace", "drills", "decisions", "inventory")
ALLOWED_ROOTS = ("topo.clab.yml", "bootstrap", "gen")
RENDER_JSON = "gen/RENDER.json"


class RenderError(Exception):
    """A renderer returned something the registry cannot write."""


@dataclass
class Context:
    """What a renderer gets beside the model.

    outdir:  where this render's files land (the lab directory, its variant directory, or a
             temporary directory during `sfab check`); renderers only need it for relative paths.
    labdir:  the lab's own directory, holding chapter.yaml.
    root:    the repo root.
    spec:    the loaded sfab.spec.Spec.
    """

    outdir: Path
    labdir: Path
    root: Path
    spec: Any
    warnings: list = field(default_factory=list)

    def rel(self, path: Path | str) -> str:
        """A path relative to the repo root, posix form, for headers and comments."""
        return Path(os.path.relpath(Path(path).resolve(), self.root)).as_posix()

    def profile_file(self, model) -> str:
        """'spec/profile-a.yaml' for the model's profile."""
        return f"spec/profile-{model.profile}.yaml"

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)


@dataclass
class RenderResult:
    outputs: dict          # path -> bytes, including gen/RENDER.json
    present: list          # renderer names that ran
    skipped: list          # renderer names not present
    warnings: list


def load_renderer(name: str):
    """Import sfab.render.<name>, or return None when the module does not exist yet."""
    mod = f"{__name__}.{name}"
    try:
        return importlib.import_module(mod)
    except ModuleNotFoundError as e:
        if e.name == mod:
            return None
        raise


def _check_path(p: str) -> str:
    pp = PurePosixPath(p)
    if pp.is_absolute() or ".." in pp.parts or not pp.parts or str(pp) != p:
        raise RenderError(f"output path {p!r} must be a clean relative posix path")
    if pp.parts[0] not in ALLOWED_ROOTS or (pp.parts[0] == "topo.clab.yml" and len(pp.parts) > 1):
        raise RenderError(f"output path {p!r} must be topo.clab.yml or under bootstrap/ or gen/")
    if p == RENDER_JSON:
        raise RenderError(f"{RENDER_JSON} is written by the registry, not by a renderer")
    return p


def _bytes(v: Any, p: str) -> bytes:
    if isinstance(v, bytes):
        return v
    if isinstance(v, str):
        return v.encode("utf-8")
    raise RenderError(f"{p}: renderer returned {type(v).__name__}, want str or bytes")


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def generator_sha(root: Path) -> str:
    """sha256 over the generator's own source (common/sfab/**/*.py, tests excluded)."""
    base = Path(root) / "common" / "sfab"
    h = hashlib.sha256()
    for p in sorted(base.rglob("*.py")):
        rel = p.relative_to(base).as_posix()
        if rel.startswith("tests/"):
            continue
        h.update(rel.encode() + b"\0" + p.read_bytes() + b"\0")
    return h.hexdigest()


def render_all(model, ctx: Context, only: tuple | None = None) -> RenderResult:
    """Run every present renderer in RENDERERS order and return the merged outputs."""
    outputs: dict[str, bytes] = {}
    owner: dict[str, str] = {}
    present, skipped = [], []
    names = only or RENDERERS
    for name in names:
        mod = load_renderer(name)
        if mod is None:
            skipped.append(name)
            ctx.warn(f"renderer {name} is not present yet; its files were not rendered")
            continue
        fn = getattr(mod, "render", None)
        if not callable(fn):
            raise RenderError(f"sfab.render.{name} has no render(model, ctx) function")
        out = fn(model, ctx) or {}
        if not isinstance(out, dict):
            raise RenderError(f"sfab.render.{name}.render returned {type(out).__name__}, want a dict")
        for p in sorted(out):
            _check_path(p)
            if p in outputs:
                raise RenderError(f"{p} is rendered by both {owner[p]} and {name}")
            outputs[p] = _bytes(out[p], p)
            owner[p] = name
        present.append(name)
    from . import inventory  # noqa: PLC0415

    outputs[RENDER_JSON] = inventory.render_json(model, ctx, outputs, present, skipped).encode("utf-8")
    return RenderResult(outputs=dict(sorted(outputs.items())), present=present, skipped=skipped, warnings=list(ctx.warnings))


def previous_files(outdir: Path) -> list[str]:
    """The files the last render wrote, from its gen/RENDER.json."""
    p = Path(outdir) / RENDER_JSON
    if not p.is_file():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return sorted((data.get("files") or {}).keys()) + [RENDER_JSON]


def write_outputs(outdir: Path | str, outputs: dict, prune: bool = True) -> list[str]:
    """Write outputs under outdir and return the paths whose content changed.

    A file whose content is unchanged is not rewritten (its mtime stays). With prune, files the
    previous render listed in gen/RENDER.json and this render no longer produces are removed,
    and directories left empty under bootstrap/ and gen/ are removed with them.
    """
    outdir = Path(outdir)
    changed = []
    old = previous_files(outdir) if prune else []
    for p, data in sorted(outputs.items()):
        if p != RENDER_JSON:
            _check_path(p)
        dst = outdir / p
        if dst.is_file() and dst.read_bytes() == data:
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        tmp = dst.with_name(dst.name + ".sfab-tmp")
        tmp.write_bytes(data)
        os.chmod(tmp, 0o644)
        os.replace(tmp, dst)
        changed.append(p)
    for p in old:
        if p in outputs:
            continue
        try:
            if p != RENDER_JSON:
                _check_path(p)
        except RenderError:
            continue
        f = outdir / p
        if f.is_file():
            f.unlink()
            changed.append(p)
            d = f.parent
            while d != outdir and d.name and not any(d.iterdir()):
                d.rmdir()
                d = d.parent
    return changed
