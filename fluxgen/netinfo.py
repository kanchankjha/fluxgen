"""
Network interface discovery helpers.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Optional

import psutil


@dataclass
class InterfaceInfo:
    name: str
    address: ipaddress._BaseInterface
    mac: str
    gateway: Optional[str]
    mtu: int = 1500


def get_interface_info(name: str, ip_version: int = 4) -> InterfaceInfo:
    addrs = psutil.net_if_addrs().get(name)
    if not addrs:
        raise ValueError(f"Interface not found: {name}")

    ipv4_addr = None
    ipv6_addr = None
    mac_addr = None
    for addr in addrs:
        if addr.family == socket.AF_INET and addr.address:
            ipv4_addr = ipaddress.ip_interface(f"{addr.address}/{addr.netmask}")
        elif addr.family == socket.AF_INET6 and addr.address:
            # Skip link-local addresses when possible
            if addr.address.lower().startswith(("fe80:", "fe80::")):
                continue
            # psutil may store scope id after % - strip it
            addr_no_scope = addr.address.split("%")[0]
            if addr.netmask:
                try:
                    prefixlen = _ipv6_prefix_length(addr.netmask)
                    ipv6_addr = ipaddress.ip_interface(f"{addr_no_scope}/{prefixlen}")
                except ValueError:
                    ipv6_addr = ipaddress.ip_interface(addr_no_scope)
            else:
                ipv6_addr = ipaddress.ip_interface(addr_no_scope)
        elif addr.family == psutil.AF_LINK and addr.address:
            mac_addr = addr.address

    chosen_addr = ipv4_addr if ip_version == 4 else ipv6_addr
    if chosen_addr is None:
        raise ValueError(f"Interface {name} does not have an IPv{ip_version} address")
    if mac_addr is None:
        raise ValueError(f"Interface {name} does not have a MAC address")

    gateway = _default_gateway(name, ip_version)
    stats = psutil.net_if_stats().get(name)
    mtu = stats.mtu if stats and stats.mtu > 0 else 1500
    return InterfaceInfo(name=name, address=chosen_addr, mac=mac_addr, gateway=gateway, mtu=mtu)


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
