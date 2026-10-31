#!/usr/bin/env python3
"""keyscrub.py: a capture's keys replaced by their marks before the capture is written anywhere.

    keyscrub.py pcap --key state/secrets/redact.key < RAW.pcap > SCRUBBED.pcap
    keyscrub.py text --key state/secrets/redact.key < DECODE.txt > SCRUBBED.txt

Chapter 7's keyed trace captures the API gateway's and the router's cluster interfaces whole, so
the HTTP headers between the in-cluster hops are in the frames, an API key in each request's
Authorization header among them. The raw pcap leaves the guest only on a pipe into this filter:
in every frame, the value of each Authorization header (after Bearer, Basic or Token when one is
there) and every token shaped like a key of the labs (sk-<org>-...-<32 hex>) is overwritten in
place by its mark, <redacted hmac:XXXXXXXXXXXX> (the first 12 hex digits of its HMAC-SHA256 under
the lab's redaction key, as common/audit/redact.py writes it), padded with '_' to the value's
length, or cut to it. Every frame keeps its length, so every offset and frame count holds; the TCP
checksum of a changed frame no longer matches its payload. A value split across two frames is
caught by its shape in each part (a key's 32 hex digits stay whole in one frame in any request a
lab sends, whose headers fit one segment), and a frame the filter cannot read is written with
every byte after the Ethernet, IP and TCP headers replaced by '_', never as it was.

The answers in those frames carry llama-server's timings (prompt_ms, prompt_per_token_ms,
prompt_per_second and the predicted_ ones, redact_tree.TIMINGS), a token rate the repository does
not publish: each such value is blanked with '_' at its length, so the frame keeps its length too.

text does the same to a decode (tcpdump -A prints the payload's lines), line by line. Both print
to standard error how many values they replaced and blanked, never a value. The key file is the lab's
state/secrets/redact.key; without one the run uses a random key of its own and says so, so its
marks match no other run's (redact.py's rule). Standard library only.
"""

from __future__ import annotations

import argparse
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "audit"))
import redact  # noqa: E402

AUTH = re.compile(rb"(?i)(authorization[ \t]*:)(?![ \t]*(?:(?:bearer|basic|token)[ \t]+)?<redacted)([ \t]*(?:(?:bearer|basic|token)[ \t]+)?)([^\r\n]+)")
KEY = re.compile(rb"sk-[a-z0-9]+(?:-[a-z0-9]+)*-[0-9a-f]{32}")
# llama-server's timings in an answer's JSON (redact_tree.TIMINGS): a rate a capture must not carry
TIMING = re.compile(redact.redact_tree_mod.TIMINGS.encode())
PAD = b"_"


def mark_bytes(value: bytes, key) -> bytes:
    m = redact.mark(value.decode("utf-8", "replace").strip(), key).encode()
    n = len(value)
    return (m + PAD * n)[:n] if n >= len(m) else m[:n]


def scrub_bytes(data: bytes, key) -> tuple:
    """(data with every Authorization value and key-shaped token marked, how many were replaced)."""
    count = 0

    def auth(m):
        nonlocal count
        count += 1
        return m.group(1) + m.group(2) + mark_bytes(m.group(3), key)

    def tok(m):
        nonlocal count
        count += 1
        return mark_bytes(m.group(0), key)

    out = AUTH.sub(auth, data)
    out = KEY.sub(tok, out)
    return out, count


def blank_timings(data: bytes) -> tuple:
    """(data with every timing value llama-server writes blanked with '_' at its length, how many)."""
    count = 0

    def blank(m):
        nonlocal count
        count += 1
        return m.group(0)[:m.start(1) - m.start(0)] + PAD * len(m.group(1))

    return TIMING.sub(blank, data), count


def _payload_offset(frame: bytes, linktype: int):
    """The offset of the TCP payload in an Ethernet (1) or Linux cooked (113, 276) frame, or None."""
    if linktype == 1:
        if len(frame) < 14:
            return None
        off, et = 14, struct.unpack("!H", frame[12:14])[0]
        while et in (0x8100, 0x88A8) and len(frame) >= off + 4:
            et = struct.unpack("!H", frame[off + 2:off + 4])[0]
            off += 4
    elif linktype == 113:
        if len(frame) < 16:
            return None
        off, et = 16, struct.unpack("!H", frame[14:16])[0]
    elif linktype == 276:
        if len(frame) < 20:
            return None
        off, et = 20, struct.unpack("!H", frame[0:2])[0]
    else:
        return None
    if et == 0x0800 and len(frame) >= off + 20:
        ihl = (frame[off] & 0x0F) * 4
        if frame[off + 9] != 6:
            return len(frame)
        off += ihl
    elif et == 0x86DD and len(frame) >= off + 40:
        if frame[off + 6] != 6:
            return len(frame)
        off += 40
    else:
        return len(frame)
    if len(frame) < off + 13:
        return len(frame)
    return off + ((frame[off + 12] >> 4) * 4)


def scrub_pcap(raw: bytes, key, counts: dict | None = None) -> tuple:
    """(the pcap with every frame's keys marked, values replaced, frames unreadable); every timing
    value blanked too, their number added to counts["timings"] when counts is given."""
    if len(raw) < 24:
        return raw, 0, 0
    magic = raw[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        e = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        e = ">"
    else:
        # not a pcap this filter knows: every byte after the first 24 is replaced
        return raw[:24] + PAD * (len(raw) - 24), 0, 1
    linktype = struct.unpack(e + "I", raw[20:24])[0] & 0x0FFFFFFF
    out = bytearray(raw[:24])
    i, total, bad = 24, 0, 0
    while i + 16 <= len(raw):
        incl = struct.unpack(e + "I", raw[i + 8:i + 12])[0]
        head, frame = raw[i:i + 16], raw[i + 16:i + 16 + incl]
        i += 16 + incl
        off = _payload_offset(frame, linktype)
        if off is None:
            new, n = PAD * len(frame), 0
            bad += 1
        else:
            body, n = scrub_bytes(frame[off:], key)
            body, nt = blank_timings(body)
            if counts is not None:
                counts["timings"] = counts.get("timings", 0) + nt
            new = frame[:off] + body
            if len(new) != len(frame):
                new, n = frame[:off] + PAD * (len(frame) - off), n
                bad += 1
        total += n
        out += head + new
    if i < len(raw):
        out += PAD * (len(raw) - i)
        bad += 1
    return bytes(out), total, bad


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="keyscrub")
    ap.add_argument("form", choices=("pcap", "text"))
    ap.add_argument("--key", default=os.path.join("state", "secrets", "redact.key"))
    a = ap.parse_args(argv)
    key = redact.read_key(a.key)
    if key is None:
        print(f"keyscrub: no redaction key in {a.key}: this run's marks use a key of their own", file=sys.stderr)
    raw = sys.stdin.buffer.read()
    if a.form == "pcap":
        counts: dict = {}
        out, n, bad = scrub_pcap(raw, key, counts)
        sys.stdout.buffer.write(out)
        print(f"keyscrub: {n} value(s) replaced by their marks, {counts.get('timings', 0)} timing value(s) blanked"
              + (f", {bad} frame(s) unreadable and blanked" if bad else ""), file=sys.stderr)
        return 0
    out, n = scrub_bytes(raw, key)
    out, nt = blank_timings(out)
    sys.stdout.buffer.write(out)
    print(f"keyscrub: {n} value(s) replaced by their marks, {nt} timing value(s) blanked", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
