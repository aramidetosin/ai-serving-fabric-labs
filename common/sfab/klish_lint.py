"""KLISH text on the SONiC 4.6.0 switches (FRAMEWORK.md sections 2.3 and 3.3).

Three things live here, because the generator and the lab-host tools must agree on them:

- parse_rendered(): how a rendered startup file reads, line by line, with the context (the
  enclosing interface or MCLAG domain block) each configuration line is typed in;
- parse_running(): how a `show running-configuration` capture reads, by indentation, with
  blocks of the same header merged (the switch prints `mclag domain 1` twice);
- lint(): every rejection of FRAMEWORK 2.3, run by `sfab lint` on each rendered file.

canonical() is the one spelling both sides are compared in: KLISH takes `interface Vlan 100`
and prints `interface Vlan100`, takes `peer-link PortChannel 1` and prints `peer-link
PortChannel1`, so an interface type and its number are joined on both sides alike.

Standard library only: common/klish/parity.py imports this module on the lab host, where
PyYAML may be missing.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

HEAD = ("configure terminal", "ip vrf mgmt", "end")
SLIRP = ipaddress.ip_network("10.0.0.0/24")
FACTORY_MTU = 9100
MTU_MIN, MTU_MAX = 1312, 9216

# Commands that open a sub-mode. Each sits directly under `configure terminal` (level 0). Only
# build A's are listed; a build B role adds its own (router bgp, address-family, ...) with the
# level it lives at, so the lint and parity follow its contexts.
OPENERS = (
    (re.compile(r"^interface\s+range\s+\S+$"), 0),
    (re.compile(r"^interface\s+[A-Za-z][A-Za-z-]*\s*[0-9][0-9/.:]*$"), 0),
    (re.compile(r"^mclag\s+domain\s+[0-9]+$"), 0),
)

# Lines that are valid at the exec prompt (outside configure terminal).
EXEC_RE = re.compile(r"^(show\s|terminal\s+length\s|write\s+memory$|clear\s|ping\s|copy\s)")

# The rendered files carry this comment before a block whose far end runs sub-interfaces at a
# given MTU (the firewall's ae1 units); the lint holds the block, and its members, to it.
FLOOR_RE = re.compile(r"^!\s*mtu-floor\s+([0-9]+)\b")

_IFREF = re.compile(r"\b(Ethernet|PortChannel|Vlan|Loopback|Management|Eth)\s+(?=[0-9])")
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
PROMPT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(\([A-Za-z0-9._/:-]*\))?#(\s|$)")
_IPV4 = re.compile(r"(?<![0-9.])([0-9]{1,3}(?:\.[0-9]{1,3}){3})(/[0-9]{1,2})?(?![0-9.])")
_GREP_BAD = re.compile(r"\bgrep\s+(?:-[A-Za-z]*E\b|[\"'])")
_MCLAG_DOMAIN = re.compile(r"^mclag\s+domain\s+([0-9]+)$")
_MCLAG_MEMBER = re.compile(r"^mclag\s+([0-9]+)$")
_PORT_HDR = re.compile(r"^interface (Ethernet[0-9]+|PortChannel[0-9]+)$")
_RANGE_HDR = re.compile(r"^interface range Ethernet([0-9]+)-([0-9]+)$")
_CHANNEL_GROUP = re.compile(r"^channel-group\s+([0-9]+)\b")
_MTU = re.compile(r"^mtu\s+([0-9]+)$")


def canonical(line: str) -> str:
    """The comparison spelling of a KLISH line: whitespace collapsed, interface type and number joined."""
    return _IFREF.sub(r"\1", " ".join(line.split()))


def is_comment(line: str) -> bool:
    """A line the launcher and the replay tool skip: blank, or starting with '!'."""
    s = line.strip()
    return not s or s.startswith("!")


def opener_level(text: str) -> int | None:
    """The level a sub-mode command lives at, or None when the line opens no sub-mode."""
    for rx, level in OPENERS:
        if rx.match(text):
            return level
    return None


@dataclass(frozen=True)
class Item:
    """One configuration line of a rendered file."""

    lineno: int        # 1-based line number in the file
    text: str          # the line as typed, stripped
    context: tuple     # canonical headers of the enclosing blocks, outermost first; () at top level
    header: bool       # the line opens a block

    @property
    def key(self) -> str:
        return canonical(self.text)


def parse_rendered(lines) -> tuple[list, list]:
    """Read a rendered KLISH file the way sonic-cli takes it.

    Returns (items, problems): items are the configuration lines with their contexts (the
    structural lines configure terminal, end and exit, comments and exec commands are not
    items); problems are structural mistakes in "line N: message: text" form.
    """
    items, found = _parse(lines)
    return items, [msg for _, msg in found]


def _parse(lines) -> tuple[list, list]:
    items: list[Item] = []
    problems: list[tuple[int, str]] = []
    mode = "exec"
    stack: list[str] = []
    for n, raw in enumerate(lines, 1):
        s = raw.strip()
        if not s or s.startswith("!"):
            continue
        if s == "configure terminal":
            if mode == "config":
                problems.append((n, f"line {n}: configure terminal typed inside configuration mode: {s}"))
            mode, stack = "config", []
            continue
        if s == "end":
            mode, stack = "exec", []
            continue
        if s == "exit":
            if stack:
                stack.pop()
            elif mode == "config":
                mode = "exec"
            continue
        if mode == "exec":
            if not EXEC_RE.match(s):
                problems.append((n, f"line {n}: configuration line outside configure terminal (it fails at the exec prompt): {s}"))
            continue
        level = opener_level(s)
        if level is not None:
            if len(stack) > level:
                problems.append((n, f"line {n}: block opened inside {stack[-1]} without an exit first: {s}"))
                stack = stack[:level]
            items.append(Item(n, s, tuple(stack), True))
            stack.append(canonical(s))
            continue
        items.append(Item(n, s, tuple(stack), False))
    return items, problems


@dataclass
class Running:
    """A `show running-configuration` capture: canonical lines by context."""

    blocks: dict = field(default_factory=dict)   # context tuple -> list of canonical lines, in order
    _sets: dict = field(default_factory=dict)

    def add(self, context: tuple, line: str) -> None:
        if line not in self._sets.setdefault(context, set()):
            self._sets[context].add(line)
            self.blocks.setdefault(context, []).append(line)

    def has(self, context: tuple, line: str) -> bool:
        return line in self._sets.get(tuple(context), ())

    def lines(self, context: tuple) -> list:
        return list(self.blocks.get(tuple(context), []))


def clean_capture_line(raw: str) -> str:
    """A capture line with carriage returns and terminal escapes removed."""
    return _ANSI.sub("", raw.replace("\r", "")).rstrip()


def parse_running(text: str) -> Running:
    """Read a running-configuration capture by indentation.

    Prompt lines (`fe-sw1# show running-configuration`), '!' separators and blank lines are
    skipped. A line's context is the chain of less-indented lines above it; blocks that share a
    header are merged, since the switch prints some blocks in two parts.
    """
    run = Running()
    stack: list[tuple[int, str]] = []
    for raw in text.splitlines():
        line = clean_capture_line(raw)
        s = line.strip()
        if not s or s.startswith("!") or PROMPT_RE.match(line):
            continue
        indent = len(line) - len(line.lstrip(" "))
        while stack and stack[-1][0] >= indent:
            stack.pop()
        c = canonical(s)
        run.add(tuple(h for _, h in stack), c)
        stack.append((indent, c))
    return run


def _addresses(text: str):
    for m in _IPV4.finditer(text):
        a, plen = m.group(1), m.group(2)
        try:
            if plen:
                yield m.group(0), ipaddress.ip_network(a + plen, strict=False)
            else:
                yield m.group(0), ipaddress.ip_network(a + "/32")
        except ValueError:
            continue


def action_problems(lines) -> list:
    """Every problem in a short KLISH session a drill or a break types (FRAMEWORK.md 4.6, 4.7):
    the session rules of lint() that hold for any session, without the startup file's head and
    admin-state rules. Rejects a `?`, an exit straight after ip vrf, a description holding a
    space, grep -E or a quoted grep pattern, no mclag domain and any address in 10.0.0.0/24."""
    out = []
    body = [str(x).strip() for x in lines if str(x).strip() and not is_comment(str(x))]
    for i, s in enumerate(body):
        if "?" in s:
            out.append(f"never type ?: {s}")
        if re.match(r"^ip\s+vrf\s+\S+$", s) and i + 1 < len(body) and body[i + 1] == "exit":
            out.append("exit after ip vrf leaves configuration mode")
        m = re.match(r"^description\s+(.*)$", s)
        if m and re.search(r"\s", m.group(1).strip()):
            out.append(f"a description must not contain a space: {s}")
        if _GREP_BAD.search(s):
            out.append(f"KLISH rejects grep -E and quoted patterns: {s}")
        if re.match(r"^no\s+mclag\s+domain\b", s):
            out.append(f"never delete an MCLAG domain: {s}")
        for tok, net in _addresses(s):
            if net.version == 4 and net.overlaps(SLIRP):
                out.append(f"{tok} is in 10.0.0.0/24: {s}")
    return out


def lint(lines, factory_mtu: int = FACTORY_MTU) -> list:
    """Every problem in a rendered KLISH startup file, as "line N: message: text" strings.

    Rejects (FRAMEWORK 2.3): a file whose first configuration lines are not configure terminal,
    ip vrf mgmt, end; a `?`; an exit straight after ip vrf; a description holding a space; grep
    -E or a quoted grep pattern; no mclag domain; mclag <id> before its mclag domain; any address
    in 10.0.0.0/24; a used port with no `no shutdown`; an mtu below the floor its far end's
    sub-interfaces need (the `! mtu-floor N` comment). Also: an mtu outside 1312 to 9216, a
    PortChannel member whose mtu differs from its PortChannel's or is typed after its
    channel-group, a configuration line outside configure terminal, and a block opened inside
    another without an exit.
    """
    lines = [str(x).rstrip("\n") for x in lines]
    problems: list[tuple[int, str]] = []

    def bad(n: int, msg: str, text: str = "") -> None:
        problems.append((n, f"line {n}: {msg}" + (f": {text}" if text else "")))

    body = [(n, ln.strip()) for n, ln in enumerate(lines, 1) if not is_comment(ln)]
    if tuple(s for _, s in body[:3]) != HEAD:
        first = body[0][0] if body else 1
        bad(first, "the file must open with configure terminal, ip vrf mgmt, end (Management0's route stays in the default table otherwise)")

    for i, (n, s) in enumerate(body):
        if "?" in s:
            bad(n, "never type ?: with a newline it runs the partial command whenever <cr> is valid", s)
        if re.match(r"^ip\s+vrf\s+\S+$", s) and i + 1 < len(body) and body[i + 1][1] == "exit":
            bad(body[i + 1][0], "exit after ip vrf leaves configuration mode (ip vrf opens no sub-mode)", "exit")
        m = re.match(r"^description\s+(.*)$", s)
        if m and re.search(r"\s", m.group(1).strip()):
            bad(n, "a description must not contain a space", s)
        if _GREP_BAD.search(s):
            bad(n, "KLISH rejects grep -E and quoted patterns; filter in the shell", s)
        if re.match(r"^no\s+mclag\s+domain\b", s):
            bad(n, "never delete an MCLAG domain (deleting and re-creating one wedges iccpd)", s)
        for tok, net in _addresses(s):
            if net.version == 4 and net.overlaps(SLIRP):
                bad(n, f"{tok} is in 10.0.0.0/24, Management0's slirp network inside every switch VM", s)
        m = _MTU.match(s)
        if m and not MTU_MIN <= int(m.group(1)) <= MTU_MAX:
            bad(n, f"mtu {m.group(1)} is outside {MTU_MIN} to {MTU_MAX}", s)

    items, structural = _parse(lines)
    problems.extend(structural)

    domains: set[str] = set()
    for it in items:
        m = _MCLAG_DOMAIN.match(it.text)
        if m and it.header:
            domains.add(m.group(1))
            continue
        m = _MCLAG_MEMBER.match(it.text)
        if m and it.context and m.group(1) not in domains:
            bad(it.lineno, f"mclag {m.group(1)} typed before mclag domain {m.group(1)} exists (KLISH answers: No instance found)", it.text)

    # Admin state and MTU per port, over every block of the same port.
    first_line: dict[str, int] = {}
    admin: dict[str, str] = {}
    mtu: dict[str, int] = {}
    group_of: dict[str, str] = {}
    for it in items:
        if it.header:
            h = canonical(it.text)
            if _PORT_HDR.match(h):
                first_line.setdefault(h, it.lineno)
            continue
        if not it.context:
            continue
        ctx = it.context[-1]
        targets = [ctx]
        rm = _RANGE_HDR.match(ctx)
        if rm:
            targets = [f"interface Ethernet{k}" for k in range(int(rm.group(1)), int(rm.group(2)) + 1)]
        for t in targets:
            if not _PORT_HDR.match(t):
                continue
            if it.text in ("shutdown", "no shutdown"):
                admin[t] = it.text
            m = _MTU.match(it.text)
            if m:
                mtu[t] = int(m.group(1))
                if t in group_of and t.startswith("interface Ethernet"):
                    bad(it.lineno, f"{t.split(' ', 1)[1]}: mtu typed after channel-group; a member's mtu goes before it joins", it.text)
            m = _CHANNEL_GROUP.match(it.text)
            if m:
                group_of[t] = f"interface PortChannel{m.group(1)}"
    for port, n in sorted(first_line.items(), key=lambda kv: kv[1]):
        if admin.get(port) != "no shutdown":
            name = port.split(" ", 1)[1]
            bad(n, f"{name} is used but not admin up: type no shutdown (the factory profile leaves every port down)", port)

    floors: dict[str, int] = {}
    pending = None
    for n, raw in enumerate(lines, 1):
        s = raw.strip()
        fm = FLOOR_RE.match(s)
        if fm:
            pending = int(fm.group(1))
            continue
        if is_comment(s):
            continue
        if pending is not None and opener_level(s) is not None:
            floors[canonical(s)] = pending
            pending = None
    for hdr, floor in sorted(floors.items()):
        have = mtu.get(hdr, factory_mtu)
        if have < floor:
            bad(first_line.get(hdr, 1), f"{hdr.split(' ', 1)[1]} runs mtu {have}, below the {floor} its far end's sub-interfaces need", hdr)
    for port, pc in sorted(group_of.items(), key=lambda kv: first_line.get(kv[0], 0)):
        want = mtu.get(pc, factory_mtu)
        have = mtu.get(port, factory_mtu)
        if have != want:
            bad(first_line.get(port, 1), f"{port.split(' ', 1)[1]} runs mtu {have} but its {pc.split(' ', 1)[1]} runs {want}; set the member's mtu before channel-group", port)

    problems.sort(key=lambda p: p[0])
    out, seen = [], set()
    for _, msg in problems:
        if msg not in seen:
            seen.add(msg)
            out.append(msg)
    return out
