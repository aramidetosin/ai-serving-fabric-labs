"""evfile: read and write a saved file that may be stored gzip-compressed.

NAME.gz holds exactly the bytes NAME held, so its lines, counted after decompressing, are the lines
the run wrote. Every reader of a saved file opens it through these helpers and accepts either form:
asked for NAME, they read NAME, or NAME.gz when only that is there.
"""

from __future__ import annotations

import gzip
import os
import zlib

GZ = ".gz"
# a compressed file is never inflated past this many bytes
MAX_INFLATE = 1 << 30


def gzip_bytes(data: bytes, level: int = 9) -> bytes:
    """data as one gzip member with no file name and a zero time stamp."""
    return gzip.compress(data, compresslevel=level, mtime=0)


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
