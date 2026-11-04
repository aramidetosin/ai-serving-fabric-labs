#!/usr/bin/env python3
"""redact: scrub credentials from a result set in place.

    redact.py [--secrets state/secrets.env] [--key state/secrets/redact.key] SET_DIR...
    redact.py [--secrets state/secrets.env] [--key state/secrets/redact.key] --stream
                                                  standard input to standard output, line by line

In every text file under each SET_DIR (a file holding a NUL byte is binary and left alone; the
gate's secret scan reads those; a file stored compressed, NAME.gz, is read decompressed and written
back compressed) it replaces:

- the value of an Authorization header, an X-PAN-KEY header, and a key= parameter;
- set-format secret lines (password, phash, secret, pre-shared-key and private-key values);
- PEM private-key blocks;
- every value in the lab's state/secrets.env, as an exact string, except the SFAB_*_USER names,
  every secret of the lab's TSIG keys (state/secrets/tsig/*.key) and every tunnel pre-shared key
  (state/secrets/ipsec/*.psk);
- the lab host's own kernel release (host-kernel, below);
- the CPU signature the PA-VM passes through from the lab host (host-cpuid, below);
- a measured throughput figure (throughput, below).

A replaced secret becomes <redacted hmac:XXXXXXXXXXXX>, the first 12 hex digits of its HMAC-SHA256
under the lab's redaction key, so a transcript still shows that a key was present and which one,
and the same value reads the same in every set of the lab, while nobody without the key can test
a guess against a mark. The key is --key, by default state/secrets/redact.key: 64 hex digits made
by common/bin/secrets.py ensure (preflight), mode 0600, gitignored with the rest of state/. When
it is missing or shorter than 32 characters, the run uses a random key of its own and says so on
standard error: its marks then match no other run's, and still give nothing away. Run it twice
and nothing more changes. Exit status is 0, or 2 when a set directory does not exist.

host-kernel. A container has no kernel of its own: whatever it prints as its kernel release is the
lab host's, for example the bonding driver's header in /proc/net/bonding ("Ethernet Channel
Bonding Driver: v<release>"), FRR's show version ("on Linux(<release>)"), uname -r and uname -a.
The release says which kernel build the lab host runs, so
it becomes [redacted: host-kernel] wherever it stands as a
whole token (after a "v", a hyphen, an underscore or a slash too: vmlinuz-<release>). A VM boots
its own kernel and prints that one, which differs from the host's and is kept; on a host that
runs the very release its VMs boot, their lines read the marker too. The release is
--host-kernel, else $SFAB_HOST_KERNEL, else the running kernel's (os.uname, on Linux only); an
empty value switches the rule off. Only the release is replaced: the rest of the host's
/proc/version (its builder's user@host, its compiler, its build date) is not, so no audit
records a container's /proc/version, dmesg or kernel log.

host-cpuid. A PA-VM's show system info prints vm-cpuid, the CPU signature the VM passes through
from the lab host's processor. It says which processor the lab host has, so the value becomes [redacted: host-cpuid] (the text
form "vm-cpuid: <value>" and the XML element). The rule is always on.

throughput. A lab proves that traffic completes on a path, not how fast. iperf3's transfer and bitrate columns become one
[redacted: throughput] marker, and so does any other rate in bits or bytes per second in the forms
tools print it (bits/sec, bit/s, kbit/s, Gbits/s, Bytes/sec, bytes/sec, B/s, kB/s, MB/s, MiB/s:
iperf3, dd, scp, apt, fio, rsync), on the line that held it. Retransmits,
the congestion window, a packet rate and a link's configured speed (Mbps, Mb/s) are kept. The
timings llama-server adds to an answer's JSON (prompt_ms, prompt_per_token_ms, prompt_per_second
and the predicted_ ones) are the other form caught: each value becomes the marker
and the token counts beside them are kept. The firewall's own rate on show
session info's "Throughput:" line (bps, kbps, Mbps) becomes the marker too. A rate written another way (in
words, or in another JSON field such as iperf3 --json's bits_per_second) is not caught, so a check
reads such output before the set is closed and records only whether the run completed. The rule is
always on.

--stream is the filter lib.sh's clab() puts after containerlab: containerlab prints the output of
any lab container that exited, and the TrueNAS launcher prints its environment, its PASSWORD among
them. Each line is written and flushed as it comes, and a
reader that goes away ends the filter quietly.
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import hmac
import io
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import evfile  # noqa: E402

MARK = "<redacted hmac:{}>"
KERNEL_MARK = "[redacted: host-kernel]"
CPUID_MARK = "[redacted: host-cpuid]"
THROUGHPUT_MARK = "[redacted: throughput]"
# the PA-VM's vm-cpuid value (group 1), as show system info prints it ("vm-cpuid: <value>") and as
# the XML API or a JSON rendering carries it; a value already replaced is not matched again
HOST_CPUID_RX = r'vm-cpuid"?[ \t]*(?::[ \t]*"?|>)(?!\[redacted)([^\s<"]+)'
HOST_CPUID = re.compile(HOST_CPUID_RX)
# a rate in the forms tools print it: iperf3's transfer and bitrate columns, dd, scp, apt, fio, rsync
THROUGHPUT_RX = r"(?:\d+(?:\.\d+)? [KMGT]?Bytes[ \t]+)?\d+(?:\.\d+)? ?(?:[kKMGT]?bits?|[kKMGT]?i?[Bb]ytes|[kKMGT]?i?B)/s(?:ec)?\b"
THROUGHPUT = re.compile(THROUGHPUT_RX)
# the timings llama-server adds to an answer's JSON (each value, group 1)
TIMINGS_RX = r'"(?:prompt|predicted)_(?:ms|per_token_ms|per_second)"[ \t]*:[ \t]*(-?\d[\d.eE+-]*)'
TIMINGS = re.compile(TIMINGS_RX)
# the firewall's own rate (group 2), the labelled line of PAN-OS show session info
FW_THROUGHPUT = re.compile(r"(?m)^([ \t]*Throughput:[ \t]+)(\d+(?:\.\d+)?[ \t]*[kKMGT]?bps)\b")
# a release stands as a whole token: no letter, digit or dot before it (a hyphen, an underscore or
# a slash may stand there: linux-image-<release>, /boot/vmlinuz-<release>, kver_<release>), except
# the "v" the bonding driver puts before it; after it no letter, digit or _ + ~ -, and a full stop
# only when it ends a sentence, so a longer release that starts with it is kept
_BEFORE = "A-Za-z0-9."
RX = [
    re.compile(r"(?im)^(\s*Authorization\s*:\s*(?:Bearer|Basic|Token)\s+)(?!<redacted)(\S+)"),
    re.compile(r"(?im)^(\s*Authorization\s*:\s*)(?!<redacted|Bearer\b|Basic\b|Token\b)(\S+)"),
    re.compile(r"(?im)^(\s*X-PAN-KEY\s*:\s*)(?!<redacted)(\S+)"),
    re.compile(r"(?i)((?:[?&\s]|^)key=)(?!<redacted)([^&\s\"'<>]+)"),
    re.compile(r"(?i)(<key>)(?!<redacted)([^<]+)(?=</key>)"),
    re.compile(r"(?im)^(\s*set\s.*?\b(?:password|phash|secret|pre-shared-key(?:\s+key)?|private-key|passphrase)\s+)(?!<redacted)(\S+)"),
]
PEM = re.compile(r"-----BEGIN ([A-Z ]*)PRIVATE KEY-----(?!\s*<redacted).*?-----END \1PRIVATE KEY-----", re.S)


# the lab's redaction key holds at least this many characters (secrets.py makes 64 hex digits)
KEY_MIN = 32
# the key a run uses when the lab has none: random, so its marks match no other run's
_RUN_KEY = os.urandom(32)


def read_key(path: str):
    """The lab's redaction key, as bytes, or None when the file is missing, unreadable or short."""
    try:
        with open(path, encoding="utf-8") as f:
            k = f.read().strip()
    except (OSError, UnicodeDecodeError):
        return None
    return k.encode("utf-8") if len(k) >= KEY_MIN else None


def mark(value: str, key: bytes | None = None) -> str:
    """The mark a redacted value leaves: the first 12 hex digits of its HMAC-SHA256 under key (the
    lab's redaction key; None is this run's own random key)."""
    digest = hmac.new(key or _RUN_KEY, value.encode("utf-8", "replace"), hashlib.sha256).hexdigest()
    return MARK.format(digest[:12])


def secret_values(path: str) -> list:
    vals = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                v = v.strip().strip("'\"")
                # user names (SFAB_*_USER) are the platforms' administrators, not secrets
                if len(v) >= 6 and not k.strip().endswith("_USER"):
                    vals.append(v)
    except OSError:
        pass
    # the lab's TSIG keys (common/bin/secrets.py), beside secrets.env in state/secrets/tsig/
    for f in sorted(glob.glob(os.path.join(os.path.dirname(os.path.abspath(path)), "secrets", "tsig", "*.key"))):
        try:
            for m in re.finditer(r'secret\s+"([^"]+)"', open(f, encoding="utf-8").read()):
                if len(m.group(1)) >= 6:
                    vals.append(m.group(1))
        except OSError:
            pass
    # the lab's tunnel pre-shared keys, in state/secrets/ipsec/
    for f in sorted(glob.glob(os.path.join(os.path.dirname(os.path.abspath(path)), "secrets", "ipsec", "*.psk"))):
        try:
            v = open(f, encoding="utf-8").read().strip()
            if len(v) >= 6:
                vals.append(v)
        except OSError:
            pass
    return sorted(set(vals), key=len, reverse=True)


def host_kernel(arg=None):
    """The lab host's kernel release: --host-kernel, else $SFAB_HOST_KERNEL, else the running
    kernel's on Linux. None when the rule is off (an empty value) or there is no release."""
    v = arg if arg is not None else os.environ.get("SFAB_HOST_KERNEL")
    if v is None:
        if not sys.platform.startswith("linux"):
            return None
        try:
            v = os.uname().release
        except AttributeError:
            return None
    v = v.strip()
    # a release has a dot; a shorter string would match far too much
    return v if len(v) >= 3 and "." in v else None


def kernel_rx(release):
    if not release:
        return None
    return re.compile(rf"(?:(?<=^v)|(?<=[^{_BEFORE}]v)|(?<![{_BEFORE}])){re.escape(release)}"
                      rf"(?![A-Za-z0-9_+~-]|\.[A-Za-z0-9])", re.M)


def redact_text(text: str, values: list, kernel=None, key: bytes | None = None) -> str:
    """kernel is kernel_rx(host_kernel()), or None to keep every kernel release; key is the lab's
    redaction key (read_key), or None for this run's own."""
    for v in values:
        if v in text:
            text = text.replace(v, mark(v, key))
    for rx in RX:
        text = rx.sub(lambda m: m.group(1) + mark(m.group(2), key), text)
    text = PEM.sub(lambda m: f"-----BEGIN {m.group(1)}PRIVATE KEY----- {mark(m.group(0), key)} -----END {m.group(1)}PRIVATE KEY-----", text)
    if kernel is not None:
        text = kernel.sub(KERNEL_MARK, text)
    if "vm-cpuid" in text:
        # group 1, the value, ends the match
        text = HOST_CPUID.sub(lambda m: m.group(0)[:m.start(1) - m.start(0)] + CPUID_MARK, text)
    if '_ms"' in text or '_per_second"' in text:
        # llama-server's timings: group 1, the value, ends the match
        text = TIMINGS.sub(lambda m: m.group(0)[:m.start(1) - m.start(0)] + THROUGHPUT_MARK, text)
    if "Throughput:" in text:
        # PAN-OS show session info's own rate line: group 2, the value, ends the match
        text = FW_THROUGHPUT.sub(lambda m: m.group(1) + THROUGHPUT_MARK, text)
    # every unit the expression knows ends in /sec or /s
    return THROUGHPUT.sub(THROUGHPUT_MARK, text) if "/s" in text else text


def read_text(path: str):
    """The text of a text file, decoded so that writing it back restores every byte, or None for a
    binary one. A compressed file is read decompressed; one that does not decompress counts as
    binary."""
    with open(path, "rb") as f:
        data = f.read()
    if evfile.is_gz(path):
        try:
            data = evfile.gunzip_bytes(data)
        except ValueError:
            return None
    if b"\0" in data:
        return None
    return data.decode("utf-8", "surrogateescape")


def redact_tree(root: str, values: list, kernel=None, key: bytes | None = None) -> int:
    """Redact every text file under root in place. The number of files changed."""
    changed = 0
    for d, _dirs, files in os.walk(root):
        for name in sorted(files):
            p = os.path.join(d, name)
            try:
                text = read_text(p)
            except OSError:
                continue
            if text is None:
                continue
            # surrogateescape: bytes that are not UTF-8 are written back as they were
            new = redact_text(text, values, kernel, key)
            if new != text:
                evfile.write_bytes(p, new.encode("utf-8", "surrogateescape"))
                changed += 1
    return changed


def stream(values: list, kernel=None, key: bytes | None = None) -> int:
    src = io.TextIOWrapper(sys.stdin.buffer, encoding="utf-8", errors="replace", newline="")
    try:
        for line in src:
            sys.stdout.write(redact_text(line, values, kernel, key))
            sys.stdout.flush()
    except BrokenPipeError:
        try:
            sys.stdout = open(os.devnull, "w")
        except OSError:
            pass
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="redact")
    ap.add_argument("--secrets", default=os.path.join("state", "secrets.env"))
    ap.add_argument("--key", default=os.path.join("state", "secrets", "redact.key"),
                    help="the lab's redaction key (secrets.py ensure makes it); without one the run uses a key of its own")
    ap.add_argument("--stream", action="store_true", help="filter standard input to standard output")
    ap.add_argument("--host-kernel", metavar="RELEASE",
                    help="the lab host's kernel release to replace (default $SFAB_HOST_KERNEL, else the running "
                         "kernel's on Linux); an empty value keeps every release")
    ap.add_argument("sets", nargs="*")
    a = ap.parse_args(argv)
    values = secret_values(a.secrets)
    kernel = kernel_rx(host_kernel(a.host_kernel))
    key = read_key(a.key)
    if key is None:
        print(f"redact: no redaction key in {a.key}: this run's marks use a key of their own", file=sys.stderr)
    if a.stream:
        return stream(values, kernel, key)
    if not a.sets:
        ap.error("name at least one SET_DIR, or --stream")
    rc = 0
    for s in a.sets:
        if not os.path.isdir(s):
            print(f"redact: no directory {s}", file=sys.stderr)
            rc = 2
            continue
        redact_tree(s, values, kernel, key)
    return rc


if __name__ == "__main__":
    sys.exit(main())
