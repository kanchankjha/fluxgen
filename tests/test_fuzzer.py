"""Coverage for normal-plus-fuzzed packet generation."""

import ipaddress
import random

import pytest
from scapy.all import ARP, Ether, IP, IPv6, SCTP, TCP, UDP

from fluxgen.config import RuntimeConfig
from fluxgen.fuzzer import _layer_fields, _packet_layers, fuzz_frame
from fluxgen.identity import Identity
from fluxgen.packet_builder import build_beast_profile, build_frames


IPV4_PROTOCOLS = (
    "tcp", "udp", "icmp", "igmp", "gre", "esp", "ah", "sctp",
    "arp", "vrrp", "ospf",
)
IPV6_PROTOCOLS = (
    "tcp", "udp", "icmp", "gre", "esp", "ah", "sctp", "vrrp", "ospf",
)

IPV4_LAYER_NAMES = {
    "tcp": "TCP", "udp": "UDP", "icmp": "ICMP", "igmp": "IGMP",
    "gre": "GRE", "esp": "ESP", "ah": "AH", "sctp": "SCTP",
    "arp": "ARP", "vrrp": "VRRP", "ospf": "OSPF_Hdr",
}
IPV6_LAYER_NAMES = {
    "tcp": "TCP", "udp": "UDP", "icmp": "ICMPv6EchoRequest",
    "gre": "GRE", "esp": "ESP", "ah": "AH", "sctp": "SCTP",
    "vrrp": "VRRPv3", "ospf": "OSPFv3_Hdr",
}


def _identity(version):
    address = "192.0.2.10" if version == 4 else "2001:db8::10"
    return Identity(ip=ipaddress.ip_address(address), mac="02:00:00:aa:bb:cc")


def _destination(version):
    return "192.0.2.20" if version == 4 else "2001:db8::20"


def _fuzzable_snapshots(frame):
    snapshots = []
    for layer in _packet_layers(frame):
        fields = _layer_fields(layer)
        if fields:
            snapshots.append(
                (layer.__class__.__name__, {name: repr(getattr(layer, name)) for name in fields})
            )
    return snapshots


@pytest.mark.parametrize("proto", IPV4_PROTOCOLS)
def test_every_ipv4_protocol_emits_normal_and_fuzzed_frames(proto):
    cfg = RuntimeConfig(
        interface="eth0",
        dst=_destination(4),
        ip_version=4,
        proto=proto,
        dport=443,
        sport=12345,
        fuzz=True,
    )

    normal, fuzzed = build_frames(
        cfg,
        _identity(4),
        _destination(4),
        "aa:bb:cc:dd:ee:ff",
        fuzz_rng=random.Random(10),
    )

    assert len(normal) == len(fuzzed)
    assert bytes(normal) != bytes(fuzzed)
    normal_layers = _fuzzable_snapshots(normal)
    fuzzed_layers = _fuzzable_snapshots(fuzzed)
    assert IPV4_LAYER_NAMES[proto] in {name for name, _ in normal_layers}
    assert [name for name, _ in normal_layers] == [name for name, _ in fuzzed_layers]
    for (_, original), (_, mutated) in zip(normal_layers, fuzzed_layers):
        assert original != mutated

    assert normal[Ether].src == fuzzed[Ether].src
    assert normal[Ether].dst == fuzzed[Ether].dst
    if proto == "arp":
        assert normal.haslayer(ARP)
        assert normal[ARP].pdst == fuzzed[ARP].pdst == _destination(4)
        assert normal[Ether].dst == "ff:ff:ff:ff:ff:ff"
    else:
        assert normal[IP].src == fuzzed[IP].src
        assert normal[IP].dst == fuzzed[IP].dst == _destination(4)
    for layer in (TCP, UDP, SCTP):
        if normal.haslayer(layer):
            assert normal[layer].dport == fuzzed[layer].dport == 443


@pytest.mark.parametrize("proto", IPV6_PROTOCOLS)
def test_every_ipv6_protocol_emits_normal_and_fuzzed_frames(proto):
    cfg = RuntimeConfig(
        interface="eth0",
        dst=_destination(6),
        ip_version=6,
        proto=proto,
        dport=443,
        sport=12345,
        fuzz=True,
    )

    normal, fuzzed = build_frames(
        cfg,
        _identity(6),
        _destination(6),
        "33:33:00:00:00:01",
        fuzz_rng=random.Random(20),
    )

    assert len(normal) == len(fuzzed)
    assert bytes(normal) != bytes(fuzzed)
    assert IPV6_LAYER_NAMES[proto] in {
        name for name, _ in _fuzzable_snapshots(normal)
    }
    for (_, original), (_, mutated) in zip(
        _fuzzable_snapshots(normal), _fuzzable_snapshots(fuzzed)
    ):
        assert original != mutated
    assert normal[IPv6].src == fuzzed[IPv6].src
    assert normal[IPv6].dst == fuzzed[IPv6].dst == _destination(6)
    for layer in (TCP, UDP, SCTP):
        if normal.haslayer(layer):
            assert normal[layer].dport == fuzzed[layer].dport == 443


def test_fuzz_seed_is_reproducible():
    cfg = RuntimeConfig(
        interface="eth0",
        dst=_destination(4),
        proto="udp",
        sport=12345,
        dport=53,
        fuzz=True,
        fuzz_seed=99,
    )
    args = (cfg, _identity(4), _destination(4), "aa:bb:cc:dd:ee:ff")

    first = build_frames(*args, fuzz_rng=random.Random(cfg.fuzz_seed))[1]
    second = build_frames(*args, fuzz_rng=random.Random(cfg.fuzz_seed))[1]

    assert bytes(first) == bytes(second)


def test_multiple_mutations_set_explicit_malformed_length_or_checksum():
    frame = Ether() / IP(dst=_destination(4)) / UDP(sport=1234, dport=53)

    fuzz_frame(frame, random.Random(7), mutations_per_header=20)

    assert frame[IP].len is not None or frame[IP].chksum is not None
    assert frame[UDP].len is not None or frame[UDP].chksum is not None
    assert len(bytes(frame)) == 42


def test_mutation_count_changes_distinct_fields_per_header():
    frame = Ether() / IP(dst=_destination(4)) / UDP(sport=1234, dport=53)
    before = _fuzzable_snapshots(frame)

    fuzz_frame(frame, random.Random(3), mutations_per_header=2)

    after = _fuzzable_snapshots(frame)
    for (_, original), (_, mutated) in zip(before, after):
        changed = sum(original[name] != mutated[name] for name in original)
        assert changed == 2


def test_sctp_data_chunk_header_is_also_fuzzed():
    cfg = RuntimeConfig(
        interface="eth0",
        dst=_destination(4),
        proto="sctp",
        dport=3868,
        payload="chunk-data",
        fuzz=True,
    )

    normal, fuzzed = build_frames(
        cfg,
        _identity(4),
        _destination(4),
        "aa:bb:cc:dd:ee:ff",
        fuzz_rng=random.Random(8),
    )

    normal_chunks = [item for item in _fuzzable_snapshots(normal) if item[0] == "SCTPChunkData"]
    fuzzed_chunks = [item for item in _fuzzable_snapshots(fuzzed) if item[0] == "SCTPChunkData"]
    assert len(normal_chunks) == len(fuzzed_chunks) == 1
    assert normal_chunks[0][1] != fuzzed_chunks[0][1]
    assert len(normal) == len(fuzzed)


@pytest.mark.parametrize("version", (4, 6))
def test_fragmentation_pairs_each_normal_fragment_with_fuzzed_copy(version):
    cfg = RuntimeConfig(
        interface="eth0",
        dst=_destination(version),
        ip_version=version,
        proto="udp",
        dport=53,
        data_size=200,
        frag=True,
        frag_size=128 if version == 6 else 64,
        fuzz=True,
    )

    frames = build_frames(
        cfg,
        _identity(version),
        _destination(version),
        "aa:bb:cc:dd:ee:ff",
        fuzz_rng=random.Random(4),
    )

    assert len(frames) > 2
    assert len(frames) % 2 == 0
    for normal, fuzzed in zip(frames[::2], frames[1::2]):
        assert len(normal) == len(fuzzed)
        assert bytes(normal) != bytes(fuzzed)
        ip_layer = IP if version == 4 else IPv6
        assert normal[ip_layer].dst == fuzzed[ip_layer].dst == _destination(version)


@pytest.mark.parametrize("version", (4, 6))
def test_beast_mode_keeps_exact_size_for_normal_and_fuzzed_variants(version):
    cfg = RuntimeConfig(
        interface="eth0",
        dst=_destination(version),
        ip_version=version,
        beast=True,
        fuzz=True,
    )
    profile = build_beast_profile(version, 1500, 10 if version == 4 else 8)

    normal, fuzzed = build_frames(
        cfg,
        _identity(version),
        _destination(version),
        "aa:bb:cc:dd:ee:ff",
        profile=profile,
        fuzz_rng=random.Random(5),
    )

    assert len(normal) == len(fuzzed) == profile.target_frame_size
    assert bytes(normal) != bytes(fuzzed)


def test_fuzz_frame_ignores_packets_without_supported_headers():
    frame = Ether() / b"payload"
    original = bytes(frame)

    result = fuzz_frame(frame, random.Random(1))

    assert result is frame
    assert bytes(frame) == original
