"""Load the spec, merge a profile with common.yaml and a variant, evaluate when: expressions,
and select one lab's model (FRAMEWORK.md sections 1.1 to 1.4).

PyYAML is needed here, at render time only; it is imported inside the functions that read YAML.
"""

from __future__ import annotations

import copy
import hashlib
import operator
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

SPEC_DIR = "spec"
CORE_FILES = ("common.yaml", "versions.yaml", "known.yaml", "klish-normalize.yaml")
FEATURES = ("k8s", "serving", "storage_setup")


class SpecError(Exception):
    """The spec or a chapter file is malformed."""


class SelectError(SpecError):
    """A chapter's selection cannot be honored (unknown slice token, a feature switched on,
    a printed device that lost an attachment, a placeholder profile, ...)."""


# --------------------------------------------------------------------------------------------
# YAML


def _yaml():
    try:
        import yaml  # noqa: PLC0415
    except ImportError:
        raise SpecError("PyYAML is not installed: the spec cannot be read (pip install pyyaml)") from None
    return yaml


def read_yaml(path: Path) -> Any:
    """Read one YAML file with the safe loader, refusing duplicate keys."""
    yaml = _yaml()

    class _Loader(yaml.SafeLoader):
        pass

    def _mapping(loader, node, deep=False):
        seen = set()
        for k, _ in node.value:
            key = loader.construct_object(k, deep=deep)
            if key in seen:
                raise SpecError(f"{path}: duplicate key {key!r} at line {k.start_mark.line + 1}")
            seen.add(key)
        return loader.construct_mapping(node, deep=deep)

    _Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)
    try:
        with open(path, encoding="utf-8") as f:
            return yaml.load(f, Loader=_Loader)  # noqa: S506 (SafeLoader subclass)
    except yaml.YAMLError as e:
        raise SpecError(f"{path}: {e}") from None


def _odd_keys(tree: Any, path: str = ""):
    """Yield paths of mapping keys that hold a space: in a YAML flow mapping, an unquoted comma
    inside a value starts a new key, so such a key is almost always a quoting mistake."""
    if isinstance(tree, dict):
        for k, v in tree.items():
            p = f"{path}.{k}" if path else str(k)
            if isinstance(k, str) and " " in k.strip():
                yield p
            yield from _odd_keys(v, p)
    elif isinstance(tree, list):
        for i, v in enumerate(tree):
            yield from _odd_keys(v, f"{path}[{i}]")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


# --------------------------------------------------------------------------------------------
# deep_merge


def _is_id_list(v: Any) -> bool:
    return isinstance(v, list) and all(isinstance(e, dict) and "id" in e for e in v)


def _strip(v: Any) -> Any:
    """Copy a value, dropping overlay markers (_delete) that have nothing to delete."""
    if isinstance(v, dict):
        return {k: _strip(x) for k, x in v.items() if not (isinstance(x, dict) and x.get("_delete") is True)}
    if isinstance(v, list):
        return [_strip(x) for x in v if not (isinstance(x, dict) and x.get("_delete") is True)]
    return copy.deepcopy(v)


def deep_merge(base: Any, over: Any) -> Any:
    """Merge over onto base and return a new tree; neither input is changed.

    - mapping + mapping: merged key by key, recursively; a key whose overlay value is a mapping
      holding `_delete: true` is removed.
    - list + list where every element of both is a mapping with an `id`: merged by id; an
      overlay element with an id already present is deep-merged into it in place, a new id is
      appended in overlay order, and `{id: x, _delete: true}` removes element x.
    - anything else: the overlay value replaces the base value.
    """
    if isinstance(base, dict) and isinstance(over, dict):
        out = {k: copy.deepcopy(v) for k, v in base.items()}
        for k, v in over.items():
            if isinstance(v, dict) and v.get("_delete") is True:
                out.pop(k, None)
            elif k in out:
                out[k] = deep_merge(out[k], v)
            else:
                out[k] = _strip(v)
        return out
    if isinstance(base, list) and isinstance(over, list) and over and _is_id_list(base) and _is_id_list(over):
        out = [copy.deepcopy(e) for e in base]
        index = {e["id"]: i for i, e in enumerate(out)}
        drop = set()
        for e in over:
            i = index.get(e["id"])
            if e.get("_delete") is True:
                if i is not None:
                    drop.add(i)
                continue
            if i is None:
                index[e["id"]] = len(out)
                out.append(_strip(e))
            else:
                out[i] = deep_merge(out[i], e)
        return [e for i, e in enumerate(out) if i not in drop]
    return _strip(over)


# --------------------------------------------------------------------------------------------
# when:


_OPS = {
    ">=": operator.ge,
    "<=": operator.le,
    "==": operator.eq,
    "!=": operator.ne,
    ">": operator.gt,
    "<": operator.lt,
}
_TERM = re.compile(r"^([a-z][a-z0-9_-]*)\s*(?:(>=|<=|==|!=|>|<)\s*([0-9]+))?$")


def parse_when(expr: Any) -> tuple[tuple[str, str | None, int | None], ...]:
    """Parse a when: expression into (state, op, step) terms. None or '' means always.

    Grammar: term ('|' term)*, where term is `state` or `state<op>step`, op one of
    >= <= == != > <, step a non-negative integer. No eval is used.
    """
    if expr is None:
        return ()
    if not isinstance(expr, str):
        raise SpecError(f"when: must be a string, got {expr!r}")
    s = expr.strip()
    if not s:
        return ()
    terms = []
    for part in s.split("|"):
        m = _TERM.match(part.strip())
        if not m:
            raise SpecError(f"when: bad term {part.strip()!r} in {expr!r}")
        st, op, n = m.group(1), m.group(2), m.group(3)
        terms.append((st, op, int(n) if n is not None else None))
    return tuple(terms)


def when(expr: Any, state: str, step: int) -> bool:
    """True when the element exists in this state and step.

    when('one', 'one', 7) is True; when('many>=9', 'many', 8) is False;
    when('one | many<=8', 'many', 8) is True; when(None, any, any) is True.
    """
    terms = parse_when(expr)
    if not terms:
        return True
    for st, op, n in terms:
        if st != state:
            continue
        if op is None or _OPS[op](step, n):
            return True
    return False


def when_states(expr: Any) -> set[str]:
    """The state names an expression mentions."""
    return {t[0] for t in parse_when(expr)}


def _walk_whens(tree: Any, path: str = ""):
    """Yield (path, expr) for every when: in the tree."""
    if isinstance(tree, dict):
        for k, v in tree.items():
            p = f"{path}.{k}" if path else str(k)
            if k == "when":
                yield path or "(top)", v
            else:
                yield from _walk_whens(v, p)
    elif isinstance(tree, list):
        for i, v in enumerate(tree):
            label = v.get("id", v.get("name", i)) if isinstance(v, dict) else i
            yield from _walk_whens(v, f"{path}[{label}]")


def check_whens(tree: dict, states: Iterable[str]) -> list[str]:
    """Return a message for every when: that does not parse or names an unknown state."""
    known = set(states)
    errs = []
    for p, expr in _walk_whens(tree):
        try:
            bad = when_states(expr) - known
        except SpecError as e:
            errs.append(f"{p}: {e}")
            continue
        if bad:
            errs.append(f"{p}: when: {expr!r} names unknown state(s) {sorted(bad)}")
    return errs


def filter_when(tree: Any, state: str, step: int) -> Any:
    """Return a copy of the tree without the elements whose when: does not hold.

    An element is a mapping inside a list, or a mapping that is the value of a key; when it
    carries `when:` and the expression is false, it is removed. The `when` key itself is
    dropped from every kept element.
    """
    if isinstance(tree, dict):
        out = {}
        for k, v in tree.items():
            if k == "when":
                continue
            if isinstance(v, dict) and "when" in v and not when(v["when"], state, step):
                continue
            out[k] = filter_when(v, state, step)
        return out
    if isinstance(tree, list):
        out = []
        for v in tree:
            if isinstance(v, dict) and "when" in v and not when(v["when"], state, step):
                continue
            out.append(filter_when(v, state, step))
        return out
    return copy.deepcopy(tree)


# --------------------------------------------------------------------------------------------
# The spec


@dataclass
class Spec:
    """The whole spec directory, as loaded by load(root)."""

    root: Path
    common: dict
    profiles: dict[str, dict]
    variants: dict[str, dict]
    versions: dict
    known: dict
    normalize: dict
    files: dict[str, str] = field(default_factory=dict)  # 'spec/x.yaml' -> sha256

    def profile_tree(self, name: str, variant: str | None = None) -> dict:
        """deep_merge(common.yaml, profile-<name>.yaml), then the variant overlay if named."""
        if name not in self.profiles:
            raise SelectError(f"no profile {name!r} (have {sorted(self.profiles)})")
        tree = deep_merge(self.common, self.profiles[name])
        if variant:
            v = self.variants.get(variant)
            if v is None:
                raise SelectError(f"no variant {variant!r} in spec/variants/ (have {sorted(self.variants)})")
            if v.get("profile") not in (None, name):
                raise SelectError(f"variant {variant!r} applies to profile {v.get('profile')!r}, not {name!r}")
            tree = deep_merge(tree, v.get("overlay") or {})
        return tree

    def files_for(self, profile: str, variant: str | None = None) -> dict[str, str]:
        """The spec files (relative path -> sha256) that feed a lab of this profile."""
        names = [f"{SPEC_DIR}/{n}" for n in CORE_FILES] + [f"{SPEC_DIR}/profile-{profile}.yaml"]
        if variant:
            names.append(f"{SPEC_DIR}/variants/{variant}.yaml")
        return {n: self.files[n] for n in sorted(names) if n in self.files}


def find_root(start: Path) -> Path:
    """Walk up from start to the repo root (the directory holding spec/common.yaml)."""
    p = Path(start).resolve()
    for d in (p, *p.parents):
        if (d / SPEC_DIR / "common.yaml").is_file():
            return d
    raise SpecError(f"no {SPEC_DIR}/common.yaml above {start}")


def load(root: Path | str) -> Spec:
    """Load spec/ under the repo root into a Spec."""
    root = Path(root).resolve()
    sd = root / SPEC_DIR
    if not (sd / "common.yaml").is_file():
        raise SpecError(f"{sd}/common.yaml not found")
    files: dict[str, str] = {}

    def rd(p: Path, default: Any = None) -> Any:
        if not p.is_file():
            if default is None:
                raise SpecError(f"{p} not found")
            return default
        files[str(p.relative_to(root).as_posix())] = sha256_file(p)
        v = read_yaml(p)
        odd = list(_odd_keys(v))
        if odd:
            raise SpecError(f"{p}: keys with spaces (quote values that contain a comma): {', '.join(odd)}")
        return {} if v is None else v

    common = rd(sd / "common.yaml")
    versions = rd(sd / "versions.yaml")
    known = rd(sd / "known.yaml")
    normalize = rd(sd / "klish-normalize.yaml")
    profiles = {}
    for p in sorted(sd.glob("profile-*.yaml")):
        name = p.stem[len("profile-"):]
        tree = rd(p)
        if tree.get("profile") != name:
            raise SpecError(f"{p}: profile: must be {name!r}")
        profiles[name] = tree
    variants = {}
    vd = sd / "variants"
    if vd.is_dir():
        for p in sorted(vd.glob("*.yaml")):
            tree = rd(p)
            if tree.get("variant") not in (None, p.stem):
                raise SpecError(f"{p}: variant: must be {p.stem!r}")
            variants[p.stem] = tree
    for name, tree in profiles.items():
        states = (tree.get("states") or {}).keys()
        errs = check_whens(tree, states)
        if errs:
            raise SpecError(f"spec/profile-{name}.yaml:\n  " + "\n  ".join(errs))
    return Spec(root=root, common=common, profiles=profiles, variants=variants,
                versions=versions, known=known, normalize=normalize, files=files)


# --------------------------------------------------------------------------------------------
# Chapter files


_LAB_CH = re.compile(r"^sfab-ch([0-9]{2})[a-z]?$")


@dataclass
class Chapter:
    """A lab's chapter.yaml, normalized."""

    lab: str
    profile: str
    state: str
    chapter: int | None
    step: int | None
    slice_nodes: tuple[str, ...]
    slice_except: tuple[str, ...]
    features: dict[str, bool]
    prints: tuple[str, ...]
    extends: str | None
    variants: dict[str, str]
    trace: dict
    drills: dict = field(default_factory=dict)
    decisions: bool = False
    tenancy: dict = field(default_factory=dict)
    path: str | None = None
    sha256: str | None = None
    raw: dict = field(default_factory=dict)


def load_chapter(path: Path | str) -> Chapter:
    """Read a lab directory's chapter.yaml (path may be the file or its directory)."""
    p = Path(path)
    if p.is_dir():
        p = p / "chapter.yaml"
    raw = read_yaml(p) or {}
    ch = chapter_from_dict(raw)
    ch.path = str(p)
    ch.sha256 = sha256_file(p)
    return ch


def chapter_from_dict(raw: dict) -> Chapter:
    """Normalize a chapter mapping (as in chapter.yaml) into a Chapter."""
    if not isinstance(raw, dict):
        raise SpecError("chapter.yaml must be a mapping")
    known_keys = {"lab", "profile", "state", "chapter", "step", "slice", "features", "prints",
                  "extends", "variants", "trace", "drills", "decisions", "tenancy", "description"}
    extra = set(raw) - known_keys
    if extra:
        raise SpecError(f"chapter.yaml: unknown keys {sorted(extra)}")
    for k in ("lab", "profile", "state"):
        if not raw.get(k):
            raise SpecError(f"chapter.yaml: {k}: is required")
    lab = str(raw["lab"])
    chapter = raw.get("chapter")
    if chapter is None:
        m = _LAB_CH.match(lab)
        chapter = int(m.group(1)) if m else None
    sl = raw.get("slice") or {}
    if isinstance(sl, list):
        sl = {"nodes": sl}
    nodes = tuple(str(x) for x in (sl.get("nodes") or ["all"]))
    exc = tuple(str(x) for x in (sl.get("except") or []))
    feats = raw.get("features") or {}
    for k, v in feats.items():
        if not isinstance(v, bool):
            raise SpecError(f"chapter.yaml: features.{k} must be true or false")
    variants = {str(k): str(v) for k, v in (raw.get("variants") or {}).items()}
    drills = raw.get("drills") or {}
    if not isinstance(drills, dict):
        raise SpecError("chapter.yaml: drills: must be a mapping")
    # decisions: true (chapter 2 on) renders the decision table and the matrix and labels every
    # object of every row (sfab.render.decisions)
    decisions = raw.get("decisions", False)
    if not isinstance(decisions, bool):
        raise SpecError("chapter.yaml: decisions: must be true or false")
    # tenancy: Part III's tool plans beside the audit's (sfab.render.tenancy): hold, the held
    # connections; isolation, Chapter 11's negative checks
    tenancy = raw.get("tenancy") or {}
    if not isinstance(tenancy, dict):
        raise SpecError("chapter.yaml: tenancy: must be a mapping")
    return Chapter(lab=lab, profile=str(raw["profile"]), state=str(raw["state"]),
                   chapter=chapter, step=raw.get("step"), slice_nodes=nodes, slice_except=exc,
                   features=dict(feats), prints=tuple(str(x) for x in (raw.get("prints") or [])),
                   extends=raw.get("extends"), variants=variants, trace=raw.get("trace") or {},
                   drills=drills, decisions=decisions, tenancy=tenancy, raw=raw)


# --------------------------------------------------------------------------------------------
# select


def pick_step(state_def: dict, chapter: Chapter) -> int:
    steps = [int(s) for s in state_def.get("steps") or []]
    if not steps:
        raise SpecError("a state needs steps:")
    mode = state_def.get("step_mode", "cumulative")
    if mode not in ("fixed", "cumulative"):
        raise SpecError(f"step_mode must be fixed or cumulative, got {mode!r}")
    if chapter.step is not None:
        if int(chapter.step) not in steps:
            raise SelectError(f"step {chapter.step} is not a step of state {chapter.state!r} ({steps})")
        return int(chapter.step)
    if mode == "fixed":
        return max(steps)
    if chapter.chapter in steps:
        return int(chapter.chapter)
    return max(steps)


def resolve_features(tree: dict, chapter: Chapter) -> dict[str, bool]:
    """State defaults, with the chapter's switches applied. A chapter may only switch off."""
    state_def = tree["states"][chapter.state]
    defaults = {k: bool(v) for k, v in (state_def.get("features") or {}).items()}
    for f in FEATURES:
        defaults.setdefault(f, False)
    feats = dict(defaults)
    for k, v in chapter.features.items():
        if k not in defaults:
            raise SelectError(f"features: unknown feature {k!r} (have {sorted(defaults)})")
        if v and not defaults[k]:
            raise SelectError(f"features: {k} is off in state {chapter.state!r}; a slice may only switch features off")
        feats[k] = bool(v)
    defs = tree.get("features") or {}
    for k, on in sorted(feats.items()):
        if not on:
            continue
        for dep in (defs.get(k) or {}).get("features") or []:
            if not feats.get(dep):
                raise SelectError(f"features: {k} needs {dep}, which is off")
    return feats


def lab_name(chapter: Chapter, variant_key: str | None) -> str:
    return f"{chapter.lab}{variant_key}" if variant_key else chapter.lab


def select(spec: Spec, chapter: Chapter | dict | str | Path, variant: str | None = None):
    """Select one lab's model (FRAMEWORK 1.4).

    chapter is a Chapter, a chapter mapping, or a path to a lab directory or its chapter.yaml.
    variant is a key of the chapter's variants: mapping (for example 'm'); the lab name gains
    it as a suffix. Returns a validated sfab.model.Model, or raises SelectError,
    SpecError or sfab.validate.ValidationError.
    """
    from . import model as _model  # noqa: PLC0415
    from . import validate as _validate  # noqa: PLC0415

    if isinstance(chapter, dict):
        ch = chapter_from_dict(chapter)
    elif isinstance(chapter, (str, Path)):
        ch = load_chapter(chapter)
    else:
        ch = chapter
    vfile = None
    if variant:
        if variant not in ch.variants:
            raise SelectError(f"variant {variant!r} is not in this chapter's variants ({sorted(ch.variants)})")
        vfile = ch.variants[variant]
    tree = spec.profile_tree(ch.profile, vfile)
    if tree.get("placeholder"):
        raise SelectError(f"profile {ch.profile!r} is a placeholder: the build {tree.get('build', '?')} milestone fills it")
    states = tree.get("states") or {}
    if ch.state not in states:
        raise SelectError(f"state {ch.state!r} is not in profile {ch.profile!r} (have {sorted(states)})")
    errs = check_whens(tree, states)
    if errs:
        raise SpecError("\n".join(errs))
    step = pick_step(states[ch.state], ch)
    filtered = filter_when(tree, ch.state, step)
    feats = resolve_features(filtered, ch)
    meta = _model.Meta(
        lab=lab_name(ch, variant),
        profile=ch.profile,
        variant=variant,
        variant_file=vfile,
        state=ch.state,
        step=step,
        chapter=ch,
        features=feats,
        versions=spec.versions,
        known=spec.known,
        normalize=spec.normalize,
        spec_files=spec.files_for(ch.profile, vfile),
        root=str(spec.root),
    )
    full = _model.build(filtered, meta, keep=None)
    _validate.validate(full)  # the whole state first: a slice must not hide a spec error
    keep = closure(full, ch, feats, filtered)
    sliced = _model.build(filtered, meta, keep=keep)
    _check_prints(full, sliced, ch)
    _validate.validate(sliced)
    return sliced


def expand_tokens(full, tokens: Iterable[str], what: str) -> set[str]:
    """Node ids for slice tokens: 'all', a node id, or a group name."""
    groups: dict[str, set[str]] = {}
    for n in full.nodes.values():
        groups.setdefault(n.group, set()).add(n.name)
    out: set[str] = set()
    for t in tokens:
        if t == "all":
            out |= set(full.nodes)
        elif t in full.nodes:
            out.add(t)
        elif t in groups:
            out |= groups[t]
        else:
            raise SelectError(f"slice {what}: {t!r} is not a node or a group in this state "
                              f"(groups: {sorted(groups)})")
    return out


def closure(full, ch: Chapter, features: dict[str, bool], tree: dict) -> set[str]:
    """The node set a slice keeps, with its dependency closure (FRAMEWORK 1.4 step 4)."""
    wanted = expand_tokens(full, ch.slice_nodes, "nodes")
    removed = expand_tokens(full, ch.slice_except, "except")
    keep = wanted - removed
    defs = tree.get("features") or {}
    why: dict[str, str] = {}
    for f, on in sorted(features.items()):
        if not on:
            continue
        for n in (defs.get(f) or {}).get("nodes") or []:
            if n not in full.nodes:
                raise SelectError(f"feature {f} needs node {n!r}, which is not in this state")
            if n not in keep:
                why[n] = f"feature {f}"
            keep.add(n)
    changed = True
    while changed:
        changed = False
        for name in sorted(keep):
            node = full.nodes[name]
            need: dict[str, str] = {}
            for r in node.requires:
                if r not in full.nodes:
                    raise SelectError(f"{name} requires {r!r}, which is not in this state")
                need[r] = f"{name} requires it"
            if node.section == "switches":
                for m in full.pair_members(name):
                    need[m] = f"pair partner of {name}"
            else:
                for link in full.links_of(name):
                    other = link.other(name)
                    if full.nodes[other.node].section == "switches":
                        need[other.node] = f"{name}'s links land on it"
            for n, reason in need.items():
                if n not in keep:
                    keep.add(n)
                    why[n] = reason
                    changed = True
    clash = keep & removed
    if clash:
        detail = ", ".join(f"{n} ({why.get(n, 'listed')})" for n in sorted(clash))
        raise SelectError(f"slice except: removes nodes the closure needs: {detail}")
    return keep


def _check_prints(full, sliced, ch: Chapter) -> None:
    kept = {l.id for l in sliced.links}
    for dev in ch.prints:
        if dev not in full.nodes:
            raise SelectError(f"prints: {dev!r} is not a node in this state")
        if dev not in sliced.nodes:
            raise SelectError(f"prints: {dev} is not in the slice")
        lost = [l for l in full.links_of(dev) if l.id not in kept]
        if lost:
            ends = ", ".join(f"{l.a} -- {l.b}" for l in lost)
            raise SelectError(f"prints: {dev} lost attachments in this slice ({ends}); "
                              f"a chapter that prints a device deploys it whole")
