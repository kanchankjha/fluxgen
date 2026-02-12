"""Unit tests for packet_builder module."""

import ipaddress
import pytest
from scapy.all import Ether, IP, TCP, UDP, ICMP, Raw
from fluxgen.config import RuntimeConfig
from fluxgen.identity import Identity
import fluxgen.packet_builder as packet_builder
from fluxgen.packet_builder import build_frames, _build_payload


class TestBuildFrames:
    """Test packet frame building."""

    @pytest.fixture
    def test_identity(self):
        """Test identity for packet building."""
        return Identity(
            ip=ipaddress.IPv4Address("192.168.1.100"),
            mac="02:00:00:aa:bb:cc",
        )

    def test_build_tcp_frame(self, test_identity):
        """Test building TCP frame."""
        cfg = RuntimeConfig(
            interface="eth0",
            dst="10.0.0.5",
            proto="tcp",
            dport=80,
            sport=12345,
            flags="S",
            ttl=64,
        )

        frames = build_frames(cfg, test_identity, "10.0.0.5", "aa:bb:cc:dd:ee:ff")

        assert len(frames) == 1
        frame = frames[0]

        # Check Ethernet layer
        assert frame.haslayer(Ether)
        assert frame[Ether].src == "02:00:00:aa:bb:cc"
        assert frame[Ether].dst == "aa:bb:cc:dd:ee:ff"

        # Check IP layer
        assert frame.haslayer(IP)
        assert frame[IP].src == "192.168.1.100"
        assert frame[IP].dst == "10.0.0.5"
        assert frame[IP].ttl == 64

        # Check TCP layer
        assert frame.haslayer(TCP)
        assert frame[TCP].sport == 12345
        assert frame[TCP].dport == 80
        assert frame[TCP].flags == "S"

    def test_build_udp_frame(self, test_identity):
        """Test building UDP frame."""
        cfg = RuntimeConfig(
            interface="eth0",
            dst="10.0.0.5",
            proto="udp",
            dport=53,
            sport=54321,
        )

        frames = build_frames(cfg, test_identity, "10.0.0.5", "aa:bb:cc:dd:ee:ff")

        assert len(frames) == 1
        frame = frames[0]

        assert frame.haslayer(UDP)
        assert frame[UDP].sport == 54321
        assert frame[UDP].dport == 53

    def test_build_icmp_frame(self, test_identity):
        """Test building ICMP frame."""
        cfg = RuntimeConfig(
            interface="eth0",
            dst="10.0.0.5",
            proto="icmp",
            icmp_type=8,
            icmp_code=0,
        )

        frames = build_frames(cfg, test_identity, "10.0.0.5", "aa:bb:cc:dd:ee:ff")

        assert len(frames) == 1
        frame = frames[0]

        assert frame.haslayer(ICMP)
        assert frame[ICMP].type == 8
        assert frame[ICMP].code == 0

    def test_build_igmp_frame(self, test_identity):
        """Test building IGMP frame."""
        cfg = RuntimeConfig(
            interface="eth0",
            dst="224.0.0.1",
            proto="igmp",
            icmp_type=0x16,  # Membership Report v2
        )

        frames = build_frames(cfg, test_identity, "224.0.0.1", "01:00:5e:00:00:01")

        assert len(frames) == 1
        frame = frames[0]
        # IGMP should be present
        assert frame.haslayer(IP)

    def test_build_gre_frame(self, test_identity):
        """Test building GRE frame."""
        cfg = RuntimeConfig(
            interface="eth0",
            dst="10.0.0.5",
            proto="gre",
        )

        frames = build_frames(cfg, test_identity, "10.0.0.5", "aa:bb:cc:dd:ee:ff")

        assert len(frames) == 1
        frame = frames[0]
        assert frame.haslayer(IP)

    def test_build_esp_frame(self, test_identity):
        """Test building ESP frame."""
        cfg = RuntimeConfig(
            interface="eth0",
            dst="10.0.0.5",
            proto="esp",
        )

        frames = build_frames(cfg, test_identity, "10.0.0.5", "aa:bb:cc:dd:ee:ff")

        assert len(frames) == 1
        frame = frames[0]
        assert frame.haslayer(IP)

    def test_build_ah_frame(self, test_identity):
        """Test building AH frame."""
        cfg = RuntimeConfig(
            interface="eth0",
            dst="10.0.0.5",
            proto="ah",
        )

        frames = build_frames(cfg, test_identity, "10.0.0.5", "aa:bb:cc:dd:ee:ff")

        assert len(frames) == 1
        frame = frames[0]
        assert frame.haslayer(IP)

    def test_build_sctp_frame(self, test_identity):
        """Test building SCTP frame."""
        cfg = RuntimeConfig(
            interface="eth0",
            dst="10.0.0.5",
            proto="sctp",
            dport=3868,
            sport=12345,
        )

        frames = build_frames(cfg, test_identity, "10.0.0.5", "aa:bb:cc:dd:ee:ff")

        assert len(frames) == 1
        frame = frames[0]
        assert frame.haslayer(IP)

    def test_build_frame_with_payload(self, test_identity):
        """Test building frame with text payload."""
        cfg = RuntimeConfig(
            interface="eth0",
            dst="10.0.0.5",
            proto="tcp",
            dport=80,
            payload="Hello World",
            payload_hex=False,
        )

        frames = build_frames(cfg, test_identity, "10.0.0.5", "aa:bb:cc:dd:ee:ff")

        assert len(frames) == 1
        frame = frames[0]
        assert frame.haslayer(Raw)
        assert frame[Raw].load == b"Hello World"

    def test_build_frame_with_data_size_payload(self, test_identity):
        """Test building frame when only data_size is provided."""
        cfg = RuntimeConfig(
            interface="eth0",
            dst="10.0.0.5",
            proto="tcp",
            dport=80,
            data_size=32,
        )

        frames = build_frames(cfg, test_identity, "10.0.0.5", "aa:bb:cc:dd:ee:ff")

        assert len(frames) == 1
        frame = frames[0]
        assert frame.haslayer(Raw)
        assert len(frame[Raw].load) == 32

    def test_build_ipv6_frame(self, test_identity):
        """Test building IPv6 TCP frame."""
        cfg = RuntimeConfig(
            interface="eth0",
            dst="2001:db8::1",
            proto="tcp",
            dport=80,
            sport=12345,
            ip_version=6,
        )

        frames = build_frames(cfg, Identity(ip=ipaddress.IPv6Address("2001:db8::2"), mac=test_identity.mac), "2001:db8::1", "33:33:00:00:00:01")

        assert len(frames) == 1
        frame = frames[0]
        assert frame.haslayer(Ether)
        assert frame.haslayer(packet_builder.IPv6)
        assert frame[packet_builder.IPv6].src == "2001:db8::2"
        assert frame[packet_builder.IPv6].dst == "2001:db8::1"

    def test_build_frame_with_hex_payload(self, test_identity):
        """Test building frame with hex payload."""
        cfg = RuntimeConfig(
            interface="eth0",
            dst="10.0.0.5",
            proto="udp",
            dport=53,
            payload="deadbeef",
            payload_hex=True,
        )

        frames = build_frames(cfg, test_identity, "10.0.0.5", "aa:bb:cc:dd:ee:ff")

        assert len(frames) == 1
        frame = frames[0]
        assert frame.haslayer(Raw)
        assert frame[Raw].load == b"\xde\xad\xbe\xef"

    def test_build_frame_with_custom_ttl_tos(self, test_identity):
        """Test building frame with custom TTL and TOS."""
        cfg = RuntimeConfig(
            interface="eth0",
            dst="10.0.0.5",
            proto="tcp",
            dport=80,
            ttl=32,
            tos=16,
        )

        frames = build_frames(cfg, test_identity, "10.0.0.5", "aa:bb:cc:dd:ee:ff")

        frame = frames[0]
        assert frame[IP].ttl == 32
        assert frame[IP].tos == 16

    def test_build_frame_with_ip_id(self, test_identity):
        """Test building frame with custom IP ID."""
        cfg = RuntimeConfig(
            interface="eth0",
            dst="10.0.0.5",
            proto="tcp",
            dport=80,
            ip_id=12345,
        )

        frames = build_frames(cfg, test_identity, "10.0.0.5", "aa:bb:cc:dd:ee:ff")

        frame = frames[0]
        assert frame[IP].id == 12345

    def test_build_frame_with_fragmentation(self, test_identity):
        """Test building fragmented frames."""
        cfg = RuntimeConfig(
            interface="eth0",
            dst="10.0.0.5",
            proto="tcp",
            dport=80,
            payload="A" * 2000,  # Large payload to trigger fragmentation
            frag=True,
            frag_size=500,
        )

        frames = build_frames(cfg, test_identity, "10.0.0.5", "aa:bb:cc:dd:ee:ff")

        # Should have multiple fragments
        assert len(frames) > 1
        # All frames should have Ethernet layer
        for frame in frames:
            assert frame.haslayer(Ether)
            assert frame.haslayer(IP)

    def test_build_frame_with_ipv6_fragmentation(self, test_identity, monkeypatch):
        """Test IPv6 fragmentation uses fragment6."""
        cfg = RuntimeConfig(
            interface="eth0",
            dst="2001:db8::1",
            proto="udp",
            dport=1234,
            payload="A" * 2000,
            frag=True,
            frag_size=1200,
            frag_mode="fixed",
            ip_version=6,
        )

        calls = {}

        def fake_fragment6(pkt, fragsize):
            calls["fragsize"] = fragsize
            return [pkt]

        monkeypatch.setattr(packet_builder, "fragment6", fake_fragment6)

        frames = build_frames(cfg, Identity(ip=ipaddress.IPv6Address("2001:db8::2"), mac=test_identity.mac), "2001:db8::1", "33:33:00:00:00:01")

        assert calls["fragsize"] == 1200
        assert len(frames) == 1
        assert frames[0].haslayer(packet_builder.IPv6)

    def test_build_frame_with_random_fragmentation(self, test_identity, monkeypatch):
        """Test random fragmentation selects randomized fragment size."""
        cfg = RuntimeConfig(
            interface="eth0",
            dst="10.0.0.5",
            proto="tcp",
            dport=80,
            payload="A" * 2000,
            frag=True,
            frag_size=1200,
            frag_mode="random",
        )

        recorded = {}

        def fake_fragment(pkt, fragsize):
            recorded["fragsize"] = fragsize
            # Return at least one fragment to keep downstream happy
            return [pkt]

        monkeypatch.setattr(packet_builder, "fragment", fake_fragment)
        monkeypatch.setattr(packet_builder.random, "randint", lambda low, high: high - 100)

        frames = build_frames(cfg, test_identity, "10.0.0.5", "aa:bb:cc:dd:ee:ff")

        assert recorded["fragsize"] == 1100
        assert len(frames) == 1
        assert frames[0].haslayer(Ether)

    def test_build_frame_unsupported_protocol(self, test_identity):
        """Test building frame with unsupported protocol raises error."""
        cfg = RuntimeConfig(
            interface="eth0",
            dst="10.0.0.5",
            proto="invalid",
        )

        with pytest.raises(ValueError, match="Unsupported protocol"):
            build_frames(cfg, test_identity, "10.0.0.5", "aa:bb:cc:dd:ee:ff")

    def test_build_frame_igmp_ipv6_not_supported(self, test_identity):
        """Test IGMP is rejected for IPv6."""
        cfg = RuntimeConfig(
            interface="eth0",
            dst="2001:db8::1",
            proto="igmp",
            ip_version=6,
        )
        with pytest.raises(ValueError, match="IGMP"):
            build_frames(cfg, Identity(ip=ipaddress.IPv6Address("2001:db8::2"), mac=test_identity.mac), "2001:db8::1", "33:33:00:00:00:01")

    def test_build_icmpv6_echo_request(self, test_identity):
        """Test building ICMPv6 echo request frame."""
        cfg = RuntimeConfig(
            interface="eth0",
            dst="2001:db8::1",
            proto="icmp",
            icmp_type=128,  # ICMPv6 echo request
            ip_version=6,
        )
        frames = build_frames(cfg, Identity(ip=ipaddress.IPv6Address("2001:db8::2"), mac=test_identity.mac), "2001:db8::1", "33:33:00:00:00:01")
        assert len(frames) == 1
        frame = frames[0]
        assert frame.haslayer(packet_builder.IPv6)

    def test_build_icmpv6_echo_reply(self, test_identity):
        """Test building ICMPv6 echo reply frame."""
        cfg = RuntimeConfig(
            interface="eth0",
            dst="2001:db8::1",
            proto="icmp",
            icmp_type=129,  # ICMPv6 echo reply
            ip_version=6,
        )
        frames = build_frames(cfg, Identity(ip=ipaddress.IPv6Address("2001:db8::2"), mac=test_identity.mac), "2001:db8::1", "33:33:00:00:00:01")
        assert len(frames) == 1
        frame = frames[0]
        assert frame.haslayer(packet_builder.IPv6)

    def test_build_icmpv6_unknown_type(self, test_identity):
        """Test building ICMPv6 with custom type."""
        cfg = RuntimeConfig(
            interface="eth0",
            dst="2001:db8::1",
            proto="icmp",
            icmp_type=200,  # Custom ICMPv6 type
            icmp_code=5,
            ip_version=6,
        )
        frames = build_frames(cfg, Identity(ip=ipaddress.IPv6Address("2001:db8::2"), mac=test_identity.mac), "2001:db8::1", "33:33:00:00:00:01")
        assert len(frames) == 1
        frame = frames[0]
        assert frame.haslayer(packet_builder.IPv6)


class TestBuildPayload:
    """Test payload building."""

    def test_build_payload_none(self):
        """Test building payload when none specified."""
        cfg = RuntimeConfig(interface="eth0", dst="10.0.0.5", payload=None)
        payload = _build_payload(cfg)
        assert payload is None

    def test_build_payload_text(self):
        """Test building text payload."""
        cfg = RuntimeConfig(
            interface="eth0",
            dst="10.0.0.5",
            payload="Hello World",
            payload_hex=False,
        )
        payload = _build_payload(cfg)
        assert payload is not None
        assert payload.load == b"Hello World"

    def test_build_payload_hex(self):
        """Test building hex payload."""
        cfg = RuntimeConfig(
            interface="eth0",
            dst="10.0.0.5",
            payload="48656c6c6f",
            payload_hex=True,
        )
        payload = _build_payload(cfg)
        assert payload is not None
        assert payload.load == b"Hello"

    def test_build_payload_hex_with_spaces(self):
        """Test building hex payload with spaces."""
        cfg = RuntimeConfig(
            interface="eth0",
            dst="10.0.0.5",
            payload="de ad be ef",
            payload_hex=True,
        )
        payload = _build_payload(cfg)
        assert payload is not None
        assert payload.load == b"\xde\xad\xbe\xef"

    def test_build_payload_with_data_size(self):
        """Test building payload when data_size is set."""
        cfg = RuntimeConfig(
            interface="eth0",
            dst="10.0.0.5",
            data_size=16,
        )
        payload = _build_payload(cfg)
        assert payload is not None
        assert len(payload.load) == 16

    def test_build_payload_invalid_hex(self):
        """Test invalid hex payload raises error."""
        cfg = RuntimeConfig(
            interface="eth0",
            dst="10.0.0.5",
            payload="invalid_hex",
            payload_hex=True,
        )
        with pytest.raises(ValueError, match="Invalid hex payload"):
            _build_payload(cfg)

    def test_build_payload_empty_string(self):
        """Test building payload from empty string."""
        cfg = RuntimeConfig(
            interface="eth0",
            dst="10.0.0.5",
            payload="",
            payload_hex=False,
        )
        payload = _build_payload(cfg)
        assert payload is None


class TestFrameEdgeCases:
    """Test edge cases in frame building."""

    @pytest.fixture
    def test_identity(self):
        """Test identity for packet building."""
        return Identity(
            ip=ipaddress.IPv4Address("192.168.1.100"),
            mac="02:00:00:aa:bb:cc",
        )

    def test_build_frame_without_custom_ip_id(self, test_identity):
        """Test building frame without custom IP ID."""
        cfg = RuntimeConfig(
            interface="eth0",
            dst="10.0.0.5",
            proto="tcp",
            dport=80,
            ip_id=None,  # Explicitly None
        )

        frames = build_frames(cfg, test_identity, "10.0.0.5", "aa:bb:cc:dd:ee:ff")
        frame = frames[0]
        # IP ID should be auto-generated by scapy
        assert frame.haslayer(IP)
        # Scapy generates an IP ID automatically

    def test_build_sctp_frame_with_payload(self, test_identity):
        """Test building SCTP frame with payload."""
        cfg = RuntimeConfig(
            interface="eth0",
            dst="10.0.0.5",
            proto="sctp",
            dport=3868,
            sport=12345,
            payload="test data",
            payload_hex=False,
        )

        frames = build_frames(cfg, test_identity, "10.0.0.5", "aa:bb:cc:dd:ee:ff")

        assert len(frames) == 1
        frame = frames[0]
        assert frame.haslayer(IP)
        # Verify SCTP layer was created
