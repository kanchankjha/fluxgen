"""
Identity pool generation for simulated clients.
"""

from __future__ import annotations

import ipaddress
import random
from dataclasses import dataclass
from typing import Iterable, List, Optional, Set


@dataclass
class Identity:
    ip: ipaddress._BaseAddress
    mac: str


def generate_identities(
    count: int,
    network: ipaddress._BaseNetwork,
    exclude_ips: Iterable[str],
    base_mac: Optional[str] = None,
) -> List[Identity]:
    excluded: Set[str] = {str(ip) for ip in exclude_ips}
    identities: List[Identity] = []
    if network.version == 4:
        hosts = [ip for ip in network.hosts() if str(ip) not in excluded]
        if len(hosts) < count:
            raise ValueError(f"Not enough usable IPs in {network} to allocate {count} clients")
        source_hosts = hosts
    else:
        available = network.num_addresses - len(excluded)
        if available < count:
            raise ValueError(f"Not enough usable IPs in {network} to allocate {count} clients")
        source_hosts = None  # Will generate randomly for IPv6

    mac_seed = _mac_seed(base_mac)
    for idx in range(count):
        if source_hosts is not None:
            ip = source_hosts[idx]
        else:
            ip = _random_ipv6_host(network, excluded, idx)
        mac = _mac_from_seed(mac_seed, idx)
        identities.append(Identity(ip=ip, mac=mac))
    return identities


def _mac_seed(base_mac: Optional[str]) -> List[int]:
    """
    Generate a MAC address seed for creating sequential addresses.

    If base_mac is provided, use it as the seed. Otherwise, generate
    a locally administered MAC with prefix 02:00:00 (the 0x02 prefix
    indicates a locally administered address, not globally unique).

    Args:
        base_mac: Optional MAC address string in format "xx:xx:xx:xx:xx:xx"

    Returns:
        List of 6 integers representing MAC bytes
    """
    if base_mac:
        try:
            parts = [int(part, 16) for part in base_mac.split(":")]
            if len(parts) != 6:
                raise ValueError
            return parts
        except ValueError as exc:
            raise ValueError(f"Invalid MAC address: {base_mac}") from exc

    # Locally administered prefix 02:00:00 with random tail
    # The 0x02 bit indicates this is not a globally unique MAC
    return [0x02, 0x00, 0x00, random.randint(0, 255), random.randint(0, 255), 0x00]


def _mac_from_seed(seed: List[int], index: int) -> str:
    """
    Generate a MAC address by incrementing the seed by index.

    Args:
        seed: Base MAC address as list of 6 bytes
        index: Offset to add to base MAC (0-based)

    Returns:
        MAC address string in format "xx:xx:xx:xx:xx:xx"
    """
    mac_bytes = seed[:]
    mac_int = 0
    for byte in mac_bytes:
        mac_int = (mac_int << 8) | byte
    mac_int = (mac_int + index + 1) % (1 << 48)
    mac = mac_int.to_bytes(6, "big")
    return ":".join(f"{byte:02x}" for byte in mac)


def _random_ipv6_host(network: ipaddress.IPv6Network, excluded: Set[str], offset: int) -> ipaddress.IPv6Address:
    """
    Generate a deterministic-but-randomized IPv6 host inside a network.
    """
    # Use deterministic seed per offset to keep reproducible across runs/tests
    rng = random.Random(offset)
    attempts = 0
    while True:
        attempts += 1
        if attempts > 1000:
            raise ValueError(f"Unable to allocate unique IPv6 addresses in {network}")
        # Avoid the network address where possible
        max_offset = network.num_addresses - 1
        if max_offset <= 0:
            candidate = network.network_address
        else:
            candidate_int = int(network.network_address) + rng.randrange(1, max_offset + 1)
            candidate = ipaddress.IPv6Address(candidate_int)
        if str(candidate) in excluded:
            continue
        excluded.add(str(candidate))
        return candidate
