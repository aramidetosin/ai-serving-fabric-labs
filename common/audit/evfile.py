"""evfile: read and write a recorded file that may be stored gzip-compressed (FRAMEWORK.md 4.4).

A result set stores its large machine-readable evidence, and a transcript over the text cap,
compressed: NAME.gz holds exactly the bytes NAME held, so its lines, counted after decompressing,
are the lines the run wrote. Every reader of a recorded file opens it through these helpers and
accepts either form: asked for NAME, they read NAME, or NAME.gz when only that is there.

The compressed form is a standard gzip member (gzip -dc and gzip.open read it) with no file name and
a zero time stamp, so the same bytes always give the same file. Its deflate stream restarts at lines
the content picks: after a line whose CRC-32 is a multiple of FLUSH_EVERY, once MIN_BLOCK bytes have
passed since the last restart. A restart depends only on that line, so two files that differ in a
few lines differ in a few blocks, and git still stores the second as a small delta of the first.
(gzip --rsyncable restarts on a rolling byte sum, which a table of near-equal lines seldom hits.)
"""

from __future__ import annotations

import gzip
import os
import struct
import zlib

GZ = ".gz"
# the deflate stream restarts after a line whose CRC-32 is a multiple of FLUSH_EVERY, at least
# MIN_BLOCK bytes after the last restart (measured on chapter 4's counter tables: FLUSH_EVERY 128 and
# MIN_BLOCK 4096 give files 23% larger than plain gzip that git packs into a fifth of the space)
FLUSH_EVERY, MIN_BLOCK = 128, 4096
# a compressed file is never inflated past this many bytes
MAX_INFLATE = 1 << 30


def gzip_bytes(data: bytes, level: int = 9) -> bytes:
    """data as one gzip member, deterministic, with content-defined flush points."""
    co = zlib.compressobj(level, zlib.DEFLATED, -15, 9)
    # magic, deflate, no flags, mtime 0, maximum compression, unknown OS
    out = [b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff"]
    mv = memoryview(data)
    start = pos = 0
    while True:
        end = data.find(b"\n", pos) + 1
        if end == 0:
            break
        if end - start >= MIN_BLOCK and zlib.crc32(mv[pos:end]) % FLUSH_EVERY == 0:
            out.append(co.compress(mv[start:end]))
            out.append(co.flush(zlib.Z_FULL_FLUSH))
            start = end
        pos = end
    out.append(co.compress(mv[start:]))
    out.append(co.flush(zlib.Z_FINISH))
    out.append(struct.pack("<II", zlib.crc32(data) & 0xFFFFFFFF, len(data) & 0xFFFFFFFF))
    return b"".join(out)


def gunzip_bytes(data: bytes, limit: int = MAX_INFLATE) -> bytes:
    """The bytes a gzip file holds; ValueError past limit or when it is not gzip."""
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        out = d.decompress(data, limit + 1)
    except zlib.error as e:
        raise ValueError(f"not a gzip file: {e}") from None
    if len(out) > limit or d.unconsumed_tail:
        raise ValueError(f"inflates past {limit} bytes")
    if not d.eof:
        raise ValueError("not a whole gzip file: it ends early")
    return out


def is_gz(path) -> bool:
    return str(path).endswith(GZ)


def plain_name(path) -> str:
    p = str(path)
    return p[:-len(GZ)] if p.endswith(GZ) else p


def resolve(path):
    """The file that holds path's bytes: path itself, or path.gz when only that exists; None when
    neither does."""
    p = str(path)
    if os.path.isfile(p):
        return p
    if not p.endswith(GZ) and os.path.isfile(p + GZ):
        return p + GZ
    return None


def read_bytes(path) -> bytes:
    """path's bytes, inflated when they are stored compressed; OSError when there is no file."""
    p = resolve(path)
    if p is None:
        raise FileNotFoundError(2, "No such file or directory", str(path))
    with open(p, "rb") as f:
        data = f.read()
    return gunzip_bytes(data) if p.endswith(GZ) else data


def read_text(path, errors: str = "replace") -> str:
    return read_bytes(path).decode("utf-8", errors)


def write_bytes(path, data: bytes) -> None:
    """Write data to path, compressed when path ends in .gz."""
    with open(path, "wb") as f:
        f.write(gzip_bytes(data) if str(path).endswith(GZ) else data)


def compress_file(path) -> str:
    """Replace path with path.gz holding the same bytes; the new path. The plain file is removed
    only after the compressed one is written and reads back equal."""
    p = str(path)
    with open(p, "rb") as f:
        data = f.read()
    tmp = p + GZ + ".tmp"
    with open(tmp, "wb") as f:
        f.write(gzip_bytes(data))
    with open(tmp, "rb") as f:
        if gzip.decompress(f.read()) != data:
            os.remove(tmp)
            raise ValueError(f"{p}: the compressed copy does not read back equal")
    os.replace(tmp, p + GZ)
    os.remove(p)
    return p + GZ
