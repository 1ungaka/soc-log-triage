"""Alert enrichment: source IP scope and allow-lists."""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Iterable

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# Explicit list instead of ipaddress.is_private, which also treats the RFC 5737
# documentation ranges (and others) as private. For a SOC, "internal" should mean
# address space your own organisation routes.
INTERNAL_NETWORKS: tuple[IPNetwork, ...] = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",  # RFC 1918
    "100.64.0.0/10",                                  # carrier-grade NAT
    "127.0.0.0/8", "169.254.0.0/16",                  # loopback, link-local
    "::1/128", "fc00::/7", "fe80::/10",               # IPv6 loopback, ULA, link-local
))


def _to_ip(value: str):
    try:
        return ipaddress.ip_address(value.strip().split("%")[0])
    except ValueError:
        return None


def ip_scope(value: str) -> str:
    """Return "internal", "external", or "" if the value is not an IP address."""
    ip = _to_ip(value) if value else None
    if ip is None:
        return ""
    if getattr(ip, "ipv4_mapped", None):
        ip = ip.ipv4_mapped
    return "internal" if any(ip in net for net in INTERNAL_NETWORKS if net.version == ip.version) else "external"


def parse_allow_list(entries: Iterable[str]) -> list[IPNetwork]:
    """Parse IPs and CIDRs. Blank lines and '#' comments are ignored; bad entries raise ValueError."""
    networks = []
    for lineno, raw in enumerate(entries, 1):
        entry = raw.split("#", 1)[0].strip()
        if not entry:
            continue
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            raise ValueError(f"invalid allow-list entry on line {lineno}: {raw.strip()!r}") from None
    return networks


def load_allow_file(path: str | Path) -> list[IPNetwork]:
    return parse_allow_list(Path(path).read_text(encoding="utf-8").splitlines())


def is_allowed(value: str, networks: Iterable[IPNetwork]) -> bool:
    ip = _to_ip(value) if value else None
    return ip is not None and any(ip.version == net.version and ip in net for net in networks)
