"""Structure-aware packet-header fuzzing helpers."""

from __future__ import annotations

import random
from typing import Any, Dict, Iterable, List, Mapping

from scapy.packet import NoPayload, Packet  # type: ignore


# Routing-critical fields (Ethernet/IP destinations and transport destination
# ports) are deliberately absent.  Explicit checksum and length values are
# included so Scapy emits malformed values instead of auto-calculating them.
_FIELDS_BY_LAYER: Mapping[str, Mapping[str, Iterable[Any]]] = {
    "IP": {
        "tos": (0, 1, 0xFF),
        "len": (0, 1, 20, 0xFFFF),
        "id": (0, 1, 0xFFFF),
        "flags": (0, 1, 2, 7),
        "frag": (0, 1, 0x1FFF),
        "ttl": (0, 1, 255),
        "chksum": (0, 1, 0xFFFF),
    },
    "IPv6": {
        "tc": (0, 1, 0xFF),
        "fl": (0, 1, 0xFFFFF),
        "plen": (0, 1, 0xFFFF),
        "hlim": (0, 1, 255),
    },
    "ARP": {
        "op": (0, 1, 2, 0xFFFF),
        "hwdst": (
            "00:00:00:00:00:00",
            "01:00:00:00:00:00",
            "ff:ff:ff:ff:ff:ff",
        ),
    },
    "TCP": {
        "sport": (0, 1, 0xFFFF),
        "seq": (0, 1, 0xFFFFFFFF),
        "ack": (0, 1, 0xFFFFFFFF),
        "dataofs": (0, 1, 5, 15),
        "reserved": (0, 1, 7),
        "flags": (0, 1, 0xFF, 0x1FF),
        "window": (0, 1, 0xFFFF),
        "chksum": (0, 1, 0xFFFF),
        "urgptr": (0, 1, 0xFFFF),
    },
    "UDP": {
        "sport": (0, 1, 0xFFFF),
        "len": (0, 1, 8, 0xFFFF),
        "chksum": (0, 1, 0xFFFF),
    },
    "ICMP": {
        "type": (0, 3, 8, 11, 0xFF),
        "code": (0, 1, 0xFF),
        "chksum": (0, 1, 0xFFFF),
    },
    "IGMP": {
        "type": (0, 0x11, 0x16, 0xFF),
        "mrcode": (0, 1, 0xFF),
        "chksum": (0, 1, 0xFFFF),
        "gaddr": ("0.0.0.0", "224.0.0.1", "255.255.255.255"),
    },
    "GRE": {
        "recursion_control": (0, 1, 7),
        "flags": (0, 1, 0x1F),
        "version": (0, 1, 7),
        "proto": (0, 0x0800, 0x86DD, 0xFFFF),
    },
    "ESP": {
        "spi": (0, 1, 0xFFFFFFFF),
        "seq": (0, 1, 0xFFFFFFFF),
    },
    "AH": {
        "nh": (0, 6, 17, 0xFF),
        "payloadlen": (0, 1, 0xFF),
        "reserved": (0, 1, 0xFFFF),
        "spi": (0, 1, 0xFFFFFFFF),
        "seq": (0, 1, 0xFFFFFFFF),
    },
    "SCTP": {
        "sport": (0, 1, 0xFFFF),
        "tag": (0, 1, 0xFFFFFFFF),
        "chksum": (0, 1, 0xFFFFFFFF),
    },
    "SCTPChunkData": {
        "type": (0, 1, 0xFF),
        "reserved": (0, 1, 15),
        "delay_sack": (0, 1),
        "unordered": (0, 1),
        "beginning": (0, 1),
        "ending": (0, 1),
        "len": (0, 1, 16, 0xFFFF),
        "tsn": (0, 1, 0xFFFFFFFF),
        "stream_id": (0, 1, 0xFFFF),
        "stream_seq": (0, 1, 0xFFFF),
        "proto_id": (0, 1, 0xFFFFFFFF),
    },
    "VRRP": {
        "version": (0, 2, 15),
        "type": (0, 1, 15),
        "vrid": (0, 1, 0xFF),
        "priority": (0, 1, 0xFF),
        "ipcount": (0, 1, 0xFF),
        "authtype": (0, 1, 0xFF),
        "adv": (0, 1, 0xFF),
        "chksum": (0, 1, 0xFFFF),
    },
    "VRRPv3": {
        "version": (0, 3, 15),
        "type": (0, 1, 15),
        "vrid": (0, 1, 0xFF),
        "priority": (0, 1, 0xFF),
        "ipcount": (0, 1, 0xFF),
        "res": (0, 15),
        "adv": (0, 1, 0xFFF),
        "chksum": (0, 1, 0xFFFF),
    },
    "OSPF_Hdr": {
        "version": (0, 2, 0xFF),
        "type": (0, 1, 5, 0xFF),
        "len": (0, 1, 24, 0xFFFF),
        "src": ("0.0.0.0", "1.1.1.1", "255.255.255.255"),
        "area": ("0.0.0.0", "0.0.0.1", "255.255.255.255"),
        "chksum": (0, 1, 0xFFFF),
        "authtype": (0, 1, 0xFFFF),
    },
    "OSPF_Hello": {
        "hellointerval": (0, 1, 0xFFFF),
        "options": (0, 1, 0xFF),
        "prio": (0, 1, 0xFF),
        "deadinterval": (0, 1, 0xFFFFFFFF),
        "router": ("0.0.0.0", "1.1.1.1", "255.255.255.255"),
        "backup": ("0.0.0.0", "1.1.1.1", "255.255.255.255"),
    },
    "OSPFv3_Hdr": {
        "version": (0, 3, 0xFF),
        "type": (0, 1, 5, 0xFF),
        "len": (0, 1, 16, 0xFFFF),
        "src": ("0.0.0.0", "1.1.1.1", "255.255.255.255"),
        "area": ("0.0.0.0", "0.0.0.1", "255.255.255.255"),
        "chksum": (0, 1, 0xFFFF),
        "instance": (0, 1, 0xFF),
        "reserved": (0, 1, 0xFF),
    },
    "OSPFv3_Hello": {
        "intid": (0, 1, 0xFFFFFFFF),
        "prio": (0, 1, 0xFF),
        "options": (0, 1, 0xFFFFFF),
        "hellointerval": (0, 1, 0xFFFF),
        "deadinterval": (0, 1, 0xFFFF),
        "router": ("0.0.0.0", "1.1.1.1", "255.255.255.255"),
        "backup": ("0.0.0.0", "1.1.1.1", "255.255.255.255"),
    },
}


def _layer_fields(layer: Packet) -> Mapping[str, Iterable[Any]]:
    """Return fuzzable fields for a Scapy layer, including ICMPv6 variants."""
    name = layer.__class__.__name__
    if name.startswith("ICMPv6"):
        fields: Dict[str, Iterable[Any]] = {
            "type": (0, 1, 128, 129, 0xFF),
            "code": (0, 1, 0xFF),
            "cksum": (0, 1, 0xFFFF),
        }
        available = {field.name for field in layer.fields_desc}
        if "id" in available:
            fields["id"] = (0, 1, 0xFFFF)
        if "seq" in available:
            fields["seq"] = (0, 1, 0xFFFF)
        return fields
    return _FIELDS_BY_LAYER.get(name, {})


def _packet_layers(frame: Packet) -> List[Packet]:
    layers: List[Packet] = []
    current: Packet = frame
    while isinstance(current, Packet) and not isinstance(current, NoPayload):
        layers.append(current)
        current = current.payload
    return layers


def fuzz_frame(frame: Packet, rng: random.Random, mutations_per_header: int = 1) -> Packet:
    """Mutate every supported header layer in ``frame`` in place.

    At least one field is changed on each recognized header.  Frame length is
    unchanged, which keeps beast-mode sizing and fragmentation stable.
    """
    operations = max(1, mutations_per_header)
    for layer in _packet_layers(frame):
        fields = _layer_fields(layer)
        if not fields:
            continue
        selected_fields = rng.sample(list(fields), k=min(operations, len(fields)))
        for field_name in selected_fields:
            current = getattr(layer, field_name)
            choices = [value for value in fields[field_name] if value != current]
            # Every mapping intentionally has at least two boundary values, so
            # a value different from the current one is always available.
            setattr(layer, field_name, rng.choice(choices))
    return frame
