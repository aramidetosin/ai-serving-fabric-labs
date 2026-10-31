#!/usr/bin/env python3
"""typescript.py IN OUT: a script(1) typescript as a plain journal (chapter 4 on: a recorded launch
runs as `script -q -c 'make up' state/rec-make-up.typescript` inside tmux, so the command printed in
the book is the command that ran, and this makes the journal the book quotes).

    typescript.py [--secrets state/secrets.env] [--key state/secrets/redact.key]
                  [--host-kernel RELEASE] IN OUT

Removes terminal control sequences (CSI, OSC, other ESC sequences, the remaining C0 controls but tab
and newline), and resolves carriage returns as the terminal showed them: a line rewritten in place
after a CR keeps the last text written, and where that text is shorter, the end of the longer text
under it; a CR before the newline is dropped. Backspaces erase the character before them, and
trailing blanks are dropped.

Then the journal goes through common/audit/redact.py's rules, as every recorded file does: the
lab's secrets become keyed marks, and the lab host's kernel release, the PA-VM's CPU signature and
a measured throughput figure their class markers (FRAMEWORK.md 4.3). The options are redact.py's,
with its defaults, which are relative to the lab directory the journal is made in. When OUT sits
in a result set (a directory just under an audits/ directory) and holds a marker, the set's
REDACTIONS.md is rebuilt. Nothing else changes.
"""
import argparse
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "audit"))
import redact  # noqa: E402

CSI = re.compile(rb"\x1b\[[0-?]*[ -/]*[@-~]")
OSC = re.compile(rb"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
ESC = re.compile(rb"\x1b[@-Z\\-_]|\x1b[()][0-9A-Za-z]|\x1b[=>78]")
C0 = re.compile(rb"[\x00-\x07\x0b\x0c\x0e-\x1a\x1c-\x1f\x7f]")


def strip(data: bytes) -> bytes:
    data = OSC.sub(b"", data)
    data = CSI.sub(b"", data)
    data = ESC.sub(b"", data)
    data = data.replace(b"\x1b", b"")
    out = []
    for line in data.split(b"\n"):
        line = line.rstrip(b"\r")
        if b"\r" in line:
            parts = [p for p in line.split(b"\r")]
            kept = parts[-1]
            # a shorter rewrite leaves the end of the longer text on screen
            for p in reversed(parts[:-1]):
                if len(p) > len(kept):
                    kept = kept + p[len(kept):]
            line = kept
        while b"\x08" in line:
            i = line.index(b"\x08")
            line = line[:max(0, i - 1)] + line[i + 1:]
        line = C0.sub(b"", line)
        out.append(line.rstrip())
    return b"\n".join(out)


def journal(data: bytes, values=(), kernel=None, key=None) -> bytes:
    """The plain journal of a typescript, with redact.py's rules applied."""
    text = (strip(data).rstrip(b"\n") + b"\n").decode("utf-8", "surrogateescape")
    return redact.redact_text(text, list(values), kernel, key).encode("utf-8", "surrogateescape")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="typescript.py", description=__doc__.split("\n\n")[0])
    ap.add_argument("--secrets", default=os.path.join("state", "secrets.env"))
    ap.add_argument("--key", default=os.path.join("state", "secrets", "redact.key"))
    ap.add_argument("--host-kernel", metavar="RELEASE",
                    help="the lab host's kernel release (default $SFAB_HOST_KERNEL, else the running kernel's on Linux)")
    ap.add_argument("src", metavar="IN")
    ap.add_argument("dst", metavar="OUT")
    a = ap.parse_args(argv)
    key = redact.read_key(a.key)
    if key is None:
        print(f"typescript: no redaction key in {a.key}: this run's marks use a key of their own", file=sys.stderr)
    with open(a.src, "rb") as f:
        data = f.read()
    out = journal(data, redact.secret_values(a.secrets), redact.kernel_rx(redact.host_kernel(a.host_kernel)), key)
    with open(a.dst, "wb") as f:
        f.write(out)
    mod = redact.redact_tree_mod
    root = mod.set_root(a.dst)
    if root is not None and b"[redacted: " in out:
        mod.write_ledger(root, mod.set_marks(root), False, when="recorded")
    return 0


if __name__ == "__main__":
    sys.exit(main())
