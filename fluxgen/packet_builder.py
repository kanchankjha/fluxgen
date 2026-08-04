"""
Packet construction helpers that mimic common hping3 flags.
"""

from __future__ import annotations

import os
import random
from dataclasses import dataclass
from typing import List, Optional

from scapy.all import (  # type: ignore
    AH,
    ESP,
    GRE,
    Ether,
    IPv6,
    ICMP,
    IP,
    SCTP,
    SCTPChunkData,
    TCP,
    UDP,
    RandShort,
    Raw,
    fragment,
    fragment6,
)
try:
    from scapy.contrib.igmp import IGMP  # type: ignore
except ImportError:
    from scapy.all import IGMP  # type: ignore

from .config import RuntimeConfig
from .identity import Identity


BEAST_PROTOCOLS_IPV4 = ("tcp", "udp", "icmp", "sctp", "gre", "esp", "ah", "igmp")
BEAST_PROTOCOLS_IPV6 = ("tcp", "udp", "icmp", "sctp", "gre", "esp", "ah")
BEAST_TCP_FLAGS = ("S", "A", "F", "R", "P", "U", "SA", "PA", "FA")


@dataclass(frozen=True)
class PacketProfile:
    """Per-packet overrides used by beast mode without mutating shared config."""

    proto: str
    target_frame_size: int
    sport: int
    dport: int
    flags: str
    ttl: int
    tos: int
    icmp_type: int
    icmp_code: int = 0


def build_beast_profile(
    ip_version: int,
    mtu: int,
    packet_index: int,
    client_index: int = 0,
    sport: Optional[int] = None,
    dport: Optional[int] = None,
) -> PacketProfile:
    """Build a varied, MTU-bounded packet profile for one client send."""
    protocols = BEAST_PROTOCOLS_IPV6 if ip_version == 6 else BEAST_PROTOCOLS_IPV4
    sequence_index = packet_index + client_index
    minimum = 74 if ip_version == 6 else 60
    maximum = max(minimum, 14 + mtu)
    target_size = minimum + (sequence_index % (maximum - minimum + 1))
    proto = protocols[sequence_index % len(protocols)]

    if ip_version == 6:
        icmp_profiles = ((128, 0), (129, 0), (1, 0), (3, 0))
    else:
        icmp_profiles = ((8, 0), (0, 0), (3, 1), (11, 0))
    icmp_type, icmp_code = icmp_profiles[sequence_index % len(icmp_profiles)]

    return PacketProfile(
        proto=proto,
        target_frame_size=target_size,
        sport=sport or random.randint(1, 65535),
        dport=dport or random.randint(1, 65535),
        flags=BEAST_TCP_FLAGS[sequence_index % len(BEAST_TCP_FLAGS)],
        ttl=random.randint(1, 255),
        tos=random.randint(0, 255),
        icmp_type=icmp_type,
        icmp_code=icmp_code,
    )


def build_frames(
    cfg: RuntimeConfig,
    identity: Identity,
    dest_ip: str,
    dest_mac: str,
    profile: Optional[PacketProfile] = None,
) -> List:
    """
    Build one or more Ethernet frames for a single send.

    Creates complete Layer 2 frames with IP, transport layer (TCP/UDP/ICMP),
    and optional payload. Supports IP fragmentation when enabled.

    Args:
        cfg: Runtime configuration
        identity: Source IP and MAC address
        dest_ip: Destination IP address
        dest_mac: Destination MAC address

    Returns:
        List of Scapy frame objects ready to send
    """
    proto = profile.proto if profile else cfg.proto
    ttl = profile.ttl if profile else cfg.ttl
    tos = profile.tos if profile else cfg.tos
    sport = profile.sport if profile else cfg.sport
    dport = profile.dport if profile else cfg.dport
    flags = profile.flags if profile else cfg.flags
    icmp_type = profile.icmp_type if profile else cfg.icmp_type
    icmp_code = profile.icmp_code if profile else cfg.icmp_code

    if cfg.ip_version == 6:
        ip_layer = IPv6(
            src=str(identity.ip),
            dst=dest_ip,
            hlim=ttl,
            tc=tos,
        )
    else:
        ip_layer = IP(
            src=str(identity.ip),
            dst=dest_ip,
            ttl=ttl,
            tos=tos,
        )
        if cfg.ip_id is not None:
            ip_layer.id = cfg.ip_id

    payload = None if profile else _build_payload(cfg)

    if proto == "tcp":
        transport = TCP(
            sport=sport or RandShort(),
            dport=dport or 0,
            flags=flags,
            seq=random.randint(0, 2**32 - 1),
            ack=0,
        )
    elif proto == "udp":
        transport = UDP(
            sport=sport or RandShort(),
            dport=dport or 0,
        )
    elif proto == "icmp":
        if cfg.ip_version == 6:
            from scapy.layers.inet6 import ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6Unknown  # type: ignore
            # Default to echo request for IPv6, but allow customization
            if icmp_type == 8 or icmp_type == 128:  # Echo request
                transport = ICMPv6EchoRequest()
            elif icmp_type == 129:  # Echo reply
                transport = ICMPv6EchoReply()
            else:
                # For other ICMPv6 types, use generic ICMPv6Unknown
                transport = ICMPv6Unknown(type=icmp_type, code=icmp_code)
        else:
            transport = ICMP(type=icmp_type, code=icmp_code)
    elif proto == "igmp":
        if cfg.ip_version == 6:
            raise ValueError("IGMP is only supported for IPv4")
        # IGMP (Internet Group Management Protocol) - multicast group management
        transport = IGMP(
            type=0x16 if profile else icmp_type,
            mrcode=0 if profile else icmp_code,
        )
    elif proto == "gre":
        # GRE (Generic Routing Encapsulation) - tunneling protocol
        transport = GRE()
    elif proto == "esp":
        # ESP (Encapsulating Security Payload) - IPsec encryption
        transport = ESP(spi=random.randint(0, 2**32 - 1))
    elif proto == "ah":
        # AH (Authentication Header) - IPsec authentication
        transport = AH(spi=random.randint(0, 2**32 - 1))
    elif proto == "sctp":
        # SCTP (Stream Control Transmission Protocol) - reliable transport
        transport = SCTP(
            sport=sport or RandShort(),
            dport=dport or 0,
        )
        # Add a basic DATA chunk for SCTP
        if payload:
            transport = transport / SCTPChunkData(data=payload.load)
            payload = None  # Already added to SCTP
    else:
        raise ValueError(f"Unsupported protocol: {proto}")

    ether = Ether(src=identity.mac, dst=dest_mac)
    base_pkt = ether / ip_layer / transport
    if payload:
        base_pkt = base_pkt / payload

    if profile:
        if len(base_pkt) > profile.target_frame_size:
            raise ValueError(
                f"Target frame size {profile.target_frame_size} is below the "
                f"{proto} minimum of {len(base_pkt)} bytes"
            )
        padding_size = profile.target_frame_size - len(base_pkt)
        if padding_size:
            base_pkt = base_pkt / Raw(load=os.urandom(padding_size))

    if cfg.frag:
        # Default fragment size is 1480 bytes (typical 1500 MTU - 20 IP header)
        fragsize = cfg.frag_size or 1480
        if cfg.frag_mode == "random":
            lower = max(8, fragsize // 2)
            fragsize = random.randint(lower, fragsize)
        if cfg.ip_version == 6:
            fragments = fragment6(base_pkt[IPv6], fragsize=fragsize)
            return [ether / frag for frag in fragments]
        fragments = fragment(base_pkt[IP], fragsize=fragsize)
        return [ether / frag for frag in fragments]
    return [base_pkt]


def _build_payload(cfg: RuntimeConfig) -> Raw | None:
    """
    Build payload from config, supporting both text and hex formats.
    """
    if cfg.payload is None:
        if cfg.data_size is not None:
            data_bytes = os.urandom(cfg.data_size)
            return Raw(load=data_bytes)
        return None
    data = cfg.payload
    if cfg.payload_hex:
        try:
            data_bytes = bytes.fromhex(data.replace(" ", ""))
        except (ValueError, AttributeError) as exc:
            raise ValueError(f"Invalid hex payload: {data}") from exc
    else:
        data_bytes = data.encode("utf-8")
    if not data_bytes:
        return None
    return Raw(load=data_bytes)
