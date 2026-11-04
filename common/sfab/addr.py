"""Prefix and host-address helpers, and the address-block checks the validator uses.

Every function takes and returns plain strings ('10.20.1.0/24', '10.20.1.21', '10.20.1.21/24'),
so renderers never handle ipaddress objects unless they want to.
"""

from __future__ import annotations

import ipaddress
from typing import Iterable

RFC1918 = tuple(ipaddress.ip_network(p) for p in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
RFC5737 = tuple(ipaddress.ip_network(p) for p in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))
RFC3849 = (ipaddress.ip_network("2001:db8::/32"),)
SLIRP = ipaddress.ip_network("10.0.0.0/24")


class AddrError(ValueError):
    """An address or prefix that does not parse or does not fit."""


def net(prefix: str):
    """Parse a prefix strictly (host bits must be zero) and return an ip_network."""
    try:
        return ipaddress.ip_network(str(prefix), strict=True)
    except ValueError as e:
        raise AddrError(f"bad prefix {prefix!r}: {e}") from None


def iface(cidr: str):
    """Parse an interface address such as '10.20.1.21/24' and return an ip_interface."""
    try:
        return ipaddress.ip_interface(str(cidr))
    except ValueError as e:
        raise AddrError(f"bad interface address {cidr!r}: {e}") from None


def ip(address: str):
    """Parse a bare address, or the address part of 'a.b.c.d/len'."""
    s = str(address)
    try:
        return ipaddress.ip_address(s.split("/")[0])
    except ValueError as e:
        raise AddrError(f"bad address {address!r}: {e}") from None


def host(prefix: str, n: int) -> str:
    """Return the n-th address of a prefix as a bare address: host('10.20.1.0/24', 21) == '10.20.1.21'.

    n counts from the network address. The network and broadcast addresses are refused for
    prefixes shorter than /31.
    """
    p = net(prefix)
    if not isinstance(n, int) or isinstance(n, bool) or n < 0:
        raise AddrError(f"host index must be a non-negative int, got {n!r}")
    if n >= p.num_addresses:
        raise AddrError(f"host {n} is outside {prefix}")
    if p.num_addresses > 2 and (n == 0 or n == p.num_addresses - 1):
        raise AddrError(f"host {n} is the network or broadcast address of {prefix}")
    return str(p.network_address + n)


def host_cidr(prefix: str, n: int) -> str:
    """Return the n-th address with the prefix length: host_cidr('10.20.1.0/24', 21) == '10.20.1.21/24'."""
    return f"{host(prefix, n)}/{net(prefix).prefixlen}"


def host32(address: str) -> str:
    """Return a host route form of an address: '10.20.1.210/32' (or /128 for IPv6)."""
    a = ip(address)
    return f"{a}/{a.max_prefixlen}"


def prefix_of(cidr: str) -> str:
    """Return the network of an interface address: prefix_of('10.20.1.21/24') == '10.20.1.0/24'."""
    return str(iface(cidr).network)


def subnet(prefix: str, new_prefixlen: int, k: int) -> str:
    """Return the k-th subnet of a given length: subnet('192.0.2.0/26', 30, 1) == '192.0.2.4/30'."""
    p = net(prefix)
    subs = list(p.subnets(new_prefix=new_prefixlen))
    if not 0 <= k < len(subs):
        raise AddrError(f"subnet {k} of /{new_prefixlen} is outside {prefix}")
    return str(subs[k])


def contains(prefix: str, address_or_prefix: str) -> bool:
    """True when an address, interface address or prefix lies inside prefix."""
    p = net(prefix)
    s = str(address_or_prefix)
    try:
        if "/" in s:
            q = ipaddress.ip_network(s, strict=False)
            if q.version != p.version:
                return False
            return q.subnet_of(p)
        a = ipaddress.ip_address(s)
    except ValueError:
        raise AddrError(f"bad address {s!r}") from None
    return a.version == p.version and a in p


def _as_net(x):
    s = str(x)
    try:
        return ipaddress.ip_network(s, strict=False)
    except ValueError:
        raise AddrError(f"bad address or prefix {s!r}") from None


def is_rfc1918(x: str) -> bool:
    """True when the address or prefix lies wholly inside 10/8, 172.16/12 or 192.168/16."""
    n = _as_net(x)
    return n.version == 4 and any(n.subnet_of(b) for b in RFC1918)


def is_rfc5737(x: str) -> bool:
    """True when the address or prefix lies wholly inside 192.0.2/24, 198.51.100/24 or 203.0.113/24."""
    n = _as_net(x)
    return n.version == 4 and any(n.subnet_of(b) for b in RFC5737)


def is_rfc3849(x: str) -> bool:
    """True when the IPv6 address or prefix lies inside the documentation prefix 2001:db8::/32."""
    n = _as_net(x)
    return n.version == 6 and any(n.subnet_of(b) for b in RFC3849)


def classify(x: str) -> str:
    """Return 'rfc1918', 'rfc5737', 'rfc3849' or 'other' for an address or prefix."""
    if is_rfc1918(x):
        return "rfc1918"
    if is_rfc5737(x):
        return "rfc5737"
    if is_rfc3849(x):
        return "rfc3849"
    return "other"


def scope_ok(scope: str, x: str) -> bool:
    """True when x fits its declared scope: internal and mgmt need RFC 1918, external RFC 5737 or RFC 3849."""
    c = classify(x)
    if scope in ("internal", "mgmt"):
        return c == "rfc1918"
    if scope == "external":
        return c in ("rfc5737", "rfc3849")
    raise AddrError(f"unknown scope {scope!r}")


def in_slirp(x: str) -> bool:
    """True when an address or prefix touches 10.0.0.0/24, the vrnetlab VMs' slirp network."""
    n = _as_net(x)
    return n.version == 4 and n.overlaps(SLIRP)


def overlaps(prefixes: Iterable[tuple[str, str]]) -> list[tuple[str, str]]:
    """Return every pair of overlapping prefixes, as id pairs, from (id, prefix) tuples."""
    items = [(i, _as_net(p)) for i, p in prefixes]
    out = []
    for a in range(len(items)):
        for b in range(a + 1, len(items)):
            ia, na = items[a]
            ib, nb = items[b]
            if na.version == nb.version and na.overlaps(nb):
                out.append((ia, ib))
    return out


def mac(prefix: str, octet: int, index: int) -> str:
    """Return a locally administered guest MAC: mac('02:5a', 111, 1) == '02:5a:6f:00:00:01'."""
    for v, what in ((octet, "octet"), (index, "index")):
        if not isinstance(v, int) or not 0 <= v <= 255:
            raise AddrError(f"mac {what} must be 0 to 255, got {v!r}")
    parts = prefix.split(":")
    if len(parts) != 2 or not all(len(p) == 2 for p in parts):
        raise AddrError(f"mac prefix must be two octets like '02:5a', got {prefix!r}")
    return f"{prefix}:{octet:02x}:00:00:{index:02x}"
