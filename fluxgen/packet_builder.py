"""
Packet construction helpers that mimic common hping3 flags.
"""

from __future__ import annotations

import os
import random
from typing import List, Sequence

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


def build_frames(
    cfg: RuntimeConfig,
    identity: Identity,
    dest_ip: str,
    dest_mac: str,
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
    if cfg.ip_version == 6:
        ip_layer = IPv6(
            src=str(identity.ip),
            dst=dest_ip,
            hlim=cfg.ttl,
            tc=cfg.tos,
        )
    else:
        ip_layer = IP(
            src=str(identity.ip),
            dst=dest_ip,
            ttl=cfg.ttl,
            tos=cfg.tos,
        )
        if cfg.ip_id is not None:
            ip_layer.id = cfg.ip_id

    payload = _build_payload(cfg)

    if cfg.proto == "tcp":
        transport = TCP(
            sport=cfg.sport or RandShort(),
            dport=cfg.dport or 0,
            flags=cfg.flags,
            seq=random.randint(0, 2**32 - 1),
            ack=0,
        )
    elif cfg.proto == "udp":
        transport = UDP(
            sport=cfg.sport or RandShort(),
            dport=cfg.dport or 0,
        )
    elif cfg.proto == "icmp":
        if cfg.ip_version == 6:
            from scapy.layers.inet6 import ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6Unknown  # type: ignore
            # Default to echo request for IPv6, but allow customization
            if cfg.icmp_type == 8 or cfg.icmp_type == 128:  # Echo request
                transport = ICMPv6EchoRequest()
            elif cfg.icmp_type == 129:  # Echo reply
                transport = ICMPv6EchoReply()
            else:
                # For other ICMPv6 types, use generic ICMPv6Unknown
                transport = ICMPv6Unknown(type=cfg.icmp_type, code=cfg.icmp_code)
        else:
            transport = ICMP(type=cfg.icmp_type, code=cfg.icmp_code)
    elif cfg.proto == "igmp":
        if cfg.ip_version == 6:
            raise ValueError("IGMP is only supported for IPv4")
        # IGMP (Internet Group Management Protocol) - multicast group management
        transport = IGMP(type=cfg.icmp_type, mrcode=cfg.icmp_code)
    elif cfg.proto == "gre":
        # GRE (Generic Routing Encapsulation) - tunneling protocol
        transport = GRE()
    elif cfg.proto == "esp":
        # ESP (Encapsulating Security Payload) - IPsec encryption
        transport = ESP(spi=random.randint(0, 2**32 - 1))
    elif cfg.proto == "ah":
        # AH (Authentication Header) - IPsec authentication
        transport = AH(spi=random.randint(0, 2**32 - 1))
    elif cfg.proto == "sctp":
        # SCTP (Stream Control Transmission Protocol) - reliable transport
        transport = SCTP(
            sport=cfg.sport or RandShort(),
            dport=cfg.dport or 0,
        )
        # Add a basic DATA chunk for SCTP
        if payload:
            transport = transport / SCTPChunkData(data=payload.load)
            payload = None  # Already added to SCTP
    else:
        raise ValueError(f"Unsupported protocol: {cfg.proto}")

    ether = Ether(src=identity.mac, dst=dest_mac)
    base_pkt = ether / ip_layer / transport
    if payload:
        base_pkt = base_pkt / payload

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
