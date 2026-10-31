"""The sfab command line: render, check, lint and show (FRAMEWORK.md section 2.1).

    sfab render <labdir> [--variant KEY] [--out DIR] [-q]
    sfab check  <labdir> [--variant KEY]
    sfab lint   <labdir> [--variant KEY]
    sfab show   <labdir> [WHAT ...] [--variant KEY]

<labdir> is a lab directory holding chapter.yaml (ch05, dev/m1). A variant renders into
<labdir>/variants/<KEY>/. WHAT is nodes (the default), links, ports [SWITCH ...], dropped,
features, budget, json, or a dotted path into the model's JSON (nodes.fe-sw1.mgmt).

Exit codes: 0 success; 1 drift (check) or lint problems; 2 a spec, selection or validation
error; 3 PyYAML is not installed (check: the committed render still deploys).
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import sys
import tempfile
from pathlib import Path

from . import render as R
from .spec import SelectError, SpecError, find_root, load, load_chapter, select
from .validate import ValidationError, problems

EXIT_OK, EXIT_DRIFT, EXIT_ERROR, EXIT_NOYAML = 0, 1, 2, 3


def _err(msg: str) -> None:
    print(f"sfab: {msg}", file=sys.stderr)


def _yaml_ok() -> bool:
    try:
        import yaml  # noqa: F401, PLC0415
    except ImportError:
        return False
    return True


def _setup(labdir: str, variant: str | None):
    lab = Path(labdir).resolve()
    if not (lab / "chapter.yaml").is_file():
        raise SpecError(f"{labdir}: no chapter.yaml")
    root = find_root(lab)
    spec = load(root)
    ch = load_chapter(lab)
    model = select(spec, ch, variant)
    outdir = lab / "variants" / variant if variant else lab
    return root, spec, lab, outdir, model


def cmd_render(a) -> int:
    root, spec, lab, outdir, model = _setup(a.labdir, a.variant)
    out = Path(a.out).resolve() if a.out else outdir
    ctx = R.Context(outdir=out, labdir=lab, root=root, spec=spec)
    res = R.render_all(model, ctx)
    for w in list(model.warnings) + res.warnings:
        _err(f"warning: {w}")
    changed = R.write_outputs(out, res.outputs)
    if not a.quiet:
        rel = os.path.relpath(out, Path.cwd())
        print(f"render {model.lab}: {len(res.outputs)} files in {rel}, {len(changed)} changed"
              + (f"; skipped renderers: {', '.join(res.skipped)}" if res.skipped else ""))
        for p in changed:
            print(f"  {p}")
    return EXIT_OK


def _render_json_core(b: bytes) -> dict:
    try:
        d = json.loads(b.decode("utf-8"))
    except ValueError:
        return {}
    d.pop("generator", None)
    return d


def cmd_check(a) -> int:
    root, spec, lab, outdir, model = _setup(a.labdir, a.variant)
    with tempfile.TemporaryDirectory(prefix="sfab-check-") as tmp:
        ctx = R.Context(outdir=Path(tmp), labdir=lab, root=root, spec=spec)
        res = R.render_all(model, ctx)
    drift = []
    for p, data in res.outputs.items():
        f = outdir / p
        if not f.is_file():
            drift.append((p, "missing from the committed render", None))
            continue
        have = f.read_bytes()
        if p == R.RENDER_JSON:
            if _render_json_core(have) != _render_json_core(data):
                drift.append((p, "differs", (have, data)))
            continue
        if have != data:
            drift.append((p, "differs", (have, data)))
    for p in R.previous_files(outdir):
        if p not in res.outputs:
            drift.append((p, "committed but no longer rendered" + (" (a renderer is missing)" if res.skipped else ""), None))
    if res.skipped:
        _err(f"warning: renderers not present: {', '.join(res.skipped)}")
    if not drift:
        print(f"check {model.lab}: clean ({len(res.outputs)} files)")
        return EXIT_OK
    print(f"check {model.lab}: {len(drift)} file(s) drifted; run `make render` and commit")
    for p, why, pair in drift:
        print(f"  {p}: {why}")
        if pair:
            have, want = pair
            try:
                diff = difflib.unified_diff(have.decode().splitlines(), want.decode().splitlines(),
                                            f"committed/{p}", f"rendered/{p}", lineterm="", n=1)
                for i, line in enumerate(diff):
                    if i >= 40:
                        print("    ...")
                        break
                    print(f"    {line}")
            except UnicodeDecodeError:
                pass
    return EXIT_DRIFT


def cmd_lint(a) -> int:
    root, spec, lab, outdir, model = _setup(a.labdir, a.variant)
    found = list(problems(model))
    klish = R.load_renderer("klish")
    if klish is not None and callable(getattr(klish, "lint", None)):
        ctx = R.Context(outdir=outdir, labdir=lab, root=root, spec=spec)
        out = klish.render(model, ctx) or {}
        for p in sorted(out):
            if p.endswith("startup-config.cfg"):
                text = out[p].decode() if isinstance(out[p], bytes) else out[p]
                for msg in klish.lint(text.splitlines()) or []:
                    found.append(f"{p}: {msg}")
    else:
        _err("warning: renderer klish (with lint) is not present; KLISH lint skipped")
    if found:
        print(f"lint {model.lab}: {len(found)} problem(s)")
        for f in found:
            print(f"  {f}")
        return EXIT_DRIFT
    print(f"lint {model.lab}: clean")
    return EXIT_OK


def _table(rows: list[list[str]]) -> str:
    if not rows:
        return ""
    w = [max(len(str(r[i])) for r in rows) for i in range(len(rows[0]))]
    return "\n".join("  ".join(str(c).ljust(w[i]) for i, c in enumerate(r)).rstrip() for r in rows)


def _show(model, what: list[str]) -> str:
    from .model import Switch  # noqa: PLC0415

    key = what[0] if what else "nodes"
    if key == "nodes":
        rows = [["NAME", "KIND", "ROLE", "GROUP", "MGMT", "CONTAINER", "NICS"]]
        for n in model.nodes.values():
            rows.append([n.name, n.kind, n.role, n.group, n.mgmt, n.container, str(len(n.nics))])
        return _table(rows)
    if key == "links":
        rows = [["ID", "KIND", "A", "B", "PC", "VLANS"]]
        for l in model.links:
            rows.append([l.id, l.kind, str(l.a), str(l.b), str(l.pc or ""), ",".join(map(str, l.vlans))])
        return _table(rows)
    if key == "dropped":
        rows = [["ID", "KIND", "A", "B"]] + [[l.id, l.kind, str(l.a), str(l.b)] for l in model.dropped]
        return _table(rows)
    if key == "ports":
        names = what[1:] or list(model.switches)
        parts = []
        for name in names:
            sw = model.node(name)
            if not isinstance(sw, Switch):
                raise SelectError(f"{name} is not a switch")
            rows = [["ETH", "NATIVE", "ROLE", "PEER", "VLAN", "PC", "DESC"]]
            pc_of = {mb.ifname: p.id for p in sw.portchannels for mb in p.members}
            for n in sw.nics:
                v = str(n.vlan) if n.vlan is not None else ",".join(map(str, n.vlans))
                rows.append([n.eth, n.native or "", n.role, str(n.peer), v, str(pc_of.get(n.eth, "")), n.desc or ""])
            parts.append(f"{sw.name} ({sw.role}, NUM_NICS {sw.num_nics})\n" + _table(rows))
        return "\n\n".join(parts)
    if key == "features":
        return "\n".join(f"{k}: {str(v).lower()}" for k, v in sorted(model.features.items()))
    if key == "budget":
        from .render.inventory import inventory  # noqa: PLC0415

        return json.dumps(inventory(model)["budget"], indent=2, sort_keys=True)
    data = model.to_json()
    if key == "json":
        return json.dumps(data, indent=2, sort_keys=True)
    cur = data
    for part in key.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            raise SelectError(f"show: no {key!r} in the model (stopped at {part!r})")
    if isinstance(cur, (dict, list)):
        return json.dumps(cur, indent=2, sort_keys=True)
    return "" if cur is None else str(cur)


def cmd_show(a) -> int:
    _, _, _, _, model = _setup(a.labdir, a.variant)
    print(_show(model, a.what))
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="sfab", description="The AI Serving Fabric lab generator")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, fn, hlp in (("render", cmd_render, "render a lab's files"),
                          ("check", cmd_check, "re-render to a temporary directory and diff against the committed render"),
                          ("lint", cmd_lint, "validation, KLISH lint and label lengths"),
                          ("show", cmd_show, "query the model")):
        sp = sub.add_parser(name, help=hlp)
        sp.add_argument("labdir")
        sp.add_argument("--variant", default=os.environ.get("VARIANT") or None)
        if name == "render":
            sp.add_argument("--out", help="write here instead of the lab directory")
            sp.add_argument("-q", "--quiet", action="store_true")
        if name == "show":
            sp.add_argument("what", nargs="*")
        sp.set_defaults(fn=fn)
    a = p.parse_args(argv)
    if not _yaml_ok():
        _err("PyYAML is not installed; the generator cannot read the spec (the committed render still deploys)")
        return EXIT_NOYAML
    try:
        return a.fn(a)
    except ValidationError as e:
        _err(str(e))
        return EXIT_ERROR
    except (SpecError, SelectError, R.RenderError, KeyError) as e:
        _err(str(e).strip("'\""))
        return EXIT_ERROR
