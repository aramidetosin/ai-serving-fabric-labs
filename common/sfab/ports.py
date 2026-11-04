"""Switch port names on the SONiC 4.6.0 image.

Container ethN is the native name Ethernet(N-1) for N 1 to 48; eth49 to eth56 are Ethernet48,
52, ... 76 (steps of 4). The standard name is Eth1/N. Only the NICs a topology connects exist
inside the VM, and NUM_NICS must be at least the highest ethN a switch uses.
"""

from __future__ import annotations

import re
from typing import Iterable

MAX_NICS = 56

_ETH_RE = re.compile(r"^eth([0-9]+)$")


class PortError(ValueError):
    """A port number or name outside what the image has."""


def eth_index(eth: int | str) -> int:
    """Return N for 'ethN' or for an int N, checking 1 <= N <= 56."""
    if isinstance(eth, bool):
        raise PortError(f"not a port: {eth!r}")
    if isinstance(eth, int):
        n = eth
    else:
        m = _ETH_RE.match(str(eth))
        if not m:
            raise PortError(f"not a container port name: {eth!r}")
        n = int(m.group(1))
    if not 1 <= n <= MAX_NICS:
        raise PortError(f"port eth{n} is outside eth1 to eth{MAX_NICS}")
    return n


def eth(n: int | str) -> str:
    """Return the container port name 'ethN'."""
    return f"eth{eth_index(n)}"


def native(n: int | str) -> str:
    """Return the native KLISH name for container port n (an int N or 'ethN').

    native(1) == 'Ethernet0', native(48) == 'Ethernet47', native(49) == 'Ethernet48',
    native(50) == 'Ethernet52', native(56) == 'Ethernet76'.
    """
    i = eth_index(n)
    if i <= 48:
        return f"Ethernet{i - 1}"
    return f"Ethernet{48 + 4 * (i - 49)}"


def standard(n: int | str) -> str:
    """Return the standard name Eth1/N (not used in rendered configuration; for reference)."""
    return f"Eth1/{eth_index(n)}"


def from_native(name: str) -> int:
    """Return container port N for a native name such as 'Ethernet3' or 'Ethernet52'."""
    m = re.match(r"^Ethernet([0-9]+)$", name)
    if not m:
        raise PortError(f"not a native port name: {name!r}")
    k = int(m.group(1))
    if k <= 47:
        return k + 1
    if k <= 76 and (k - 48) % 4 == 0:
        return 49 + (k - 48) // 4
    raise PortError(f"{name} does not exist on this image")


def native_range(ns: Iterable[int | str]) -> str:
    """Return a KLISH range for contiguous ports, for `interface range`.

    native_range([1, 2]) == 'Ethernet0-1'. The ports must be contiguous and all at or below 48,
    since the native numbering steps by 4 above 48.
    """
    idx = sorted({eth_index(n) for n in ns})
    if not idx:
        raise PortError("empty port range")
    if idx[-1] > 48:
        raise PortError("native_range covers eth1 to eth48 only")
    if idx != list(range(idx[0], idx[-1] + 1)):
        raise PortError(f"ports are not contiguous: {idx}")
    if len(idx) == 1:
        return native(idx[0])
    return f"Ethernet{idx[0] - 1}-{idx[-1] - 1}"


def num_nics(sw_or_ports, sflow: bool | None = None) -> int:
    """Return the NUM_NICS value for a switch.

    Accepts a model Switch (its used ports and sflow flag are read) or an iterable of port
    numbers. The value is the highest ethN connected, or 56 when the switch exports sFlow, in
    which case eth56 must be cabled (validate checks that).
    """
    if hasattr(sw_or_ports, "used_ports"):
        ports = list(sw_or_ports.used_ports)
        if sflow is None:
            sflow = bool(getattr(sw_or_ports, "sflow", False))
    else:
        ports = [eth_index(p) for p in sw_or_ports]
    if sflow:
        return MAX_NICS
    if not ports:
        return 1
    return max(ports)
