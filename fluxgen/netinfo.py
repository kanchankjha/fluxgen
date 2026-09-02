"""
Network interface discovery helpers.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import List, Optional

import psutil


@dataclass
class InterfaceInfo:
    name: str
    address: ipaddress._BaseInterface
    mac: str
    gateway: Optional[str]
    mtu: int = 1500


def get_interface_info(name: str, ip_version: int = 4) -> InterfaceInfo:
    infos = get_interface_infos(name, ip_version=ip_version)
    return infos[-1]


def get_interface_infos(name: str, ip_version: int = 0) -> List[InterfaceInfo]:
    """Return eligible interface addresses, optionally filtered by family.

    ``ip_version=0`` is used by the independent responder to discover both
    IPv4 and non-link-local IPv6 addresses from one interface.
    """
    addrs = psutil.net_if_addrs().get(name)
    if not addrs:
        raise ValueError(f"Interface not found: {name}")

    addresses = []
    mac_addr = None
    for addr in addrs:
        if addr.family == socket.AF_INET and addr.address:
            if ip_version in (0, 4):
                addresses.append(ipaddress.ip_interface(f"{addr.address}/{addr.netmask}"))
        elif addr.family == socket.AF_INET6 and addr.address:
            # Skip link-local addresses when possible
            if addr.address.lower().startswith(("fe80:", "fe80::")):
                continue
            # psutil may store scope id after % - strip it
            addr_no_scope = addr.address.split("%")[0]
            if addr.netmask:
                try:
                    prefixlen = _ipv6_prefix_length(addr.netmask)
                    parsed = ipaddress.ip_interface(f"{addr_no_scope}/{prefixlen}")
                except ValueError:
                    parsed = ipaddress.ip_interface(addr_no_scope)
            else:
                parsed = ipaddress.ip_interface(addr_no_scope)
            if ip_version in (0, 6):
                addresses.append(parsed)
        elif addr.family == psutil.AF_LINK and addr.address:
            mac_addr = addr.address

    if not addresses:
        family = f"IPv{ip_version}" if ip_version in (4, 6) else "IPv4/IPv6"
        raise ValueError(f"Interface {name} does not have an {family} address")
    if mac_addr is None:
        raise ValueError(f"Interface {name} does not have a MAC address")

    stats = psutil.net_if_stats().get(name)
    mtu = stats.mtu if stats and stats.mtu > 0 else 1500
    infos = []
    for address in addresses:
        gateway = _default_gateway(name, address.version)
        infos.append(InterfaceInfo(name=name, address=address, mac=mac_addr, gateway=gateway, mtu=mtu))
    return infos


def _ipv6_prefix_length(netmask: str) -> int:
    """Return a prefix length for psutil's platform-dependent IPv6 netmask."""
    value = str(netmask).split("%", 1)[0].strip()
    if value.startswith("/"):
        value = value[1:]

    if value.isdigit():
        prefixlen = int(value)
        if 0 <= prefixlen <= 128:
            return prefixlen
        raise ValueError(f"Invalid IPv6 prefix length: {netmask}")

    mask = int(ipaddress.IPv6Address(value))
    prefixlen = mask.bit_count()
    expected = ((1 << prefixlen) - 1) << (128 - prefixlen) if prefixlen else 0
    if mask != expected:
        raise ValueError(f"Non-contiguous IPv6 netmask: {netmask}")
    return prefixlen


def _default_gateway(iface: str, ip_version: int = 4) -> Optional[str]:
    try:
        import netifaces  # type: ignore
    except ImportError:  # pragma: no cover - optional dependency
        return None

    gateways = netifaces.gateways()
    family = netifaces.AF_INET if ip_version == 4 else netifaces.AF_INET6
    default_gw = gateways.get("default", {}).get(family)
    if not default_gw:
        return None
    gw_ip, gw_iface = default_gw[0], default_gw[1]
    if gw_iface != iface:
        return None
    return gw_ip
