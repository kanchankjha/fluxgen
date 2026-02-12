"""Unit tests for sender module."""

import ipaddress
import time
import pytest
from unittest.mock import MagicMock, Mock, patch
from fluxgen.sender import Simulator, SendStats, _build_dest_pool
from fluxgen.config import RuntimeConfig


@pytest.fixture
def mock_sleep():
    """Mock time.sleep to prevent delays in tests."""
    with patch("fluxgen.sender.time.sleep") as mock:
        yield mock


class TestSendStats:
    """Test SendStats class."""

    def test_sendstats_bump_sent(self):
        """Test incrementing sent counter."""
        stats = SendStats()
        assert stats.sent == 0
        stats.bump_sent()
        assert stats.sent == 1
        stats.bump_sent(5)
        assert stats.sent == 6

    def test_sendstats_bump_error(self):
        """Test incrementing error counter."""
        stats = SendStats()
        assert stats.errors == 0
        stats.bump_error()
        assert stats.errors == 1
        stats.bump_error(3)
        assert stats.errors == 4

    def test_sendstats_thread_safe(self):
        """Test stats are thread-safe with concurrent access."""
        import threading
        stats = SendStats()

        def increment():
            for _ in range(100):
                stats.bump_sent()

        threads = [threading.Thread(target=increment) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert stats.sent == 1000


class TestBuildDestPool:
    """Test destination pool building."""

    def test_build_dest_pool_single_dst(self):
        """Test building pool with single destination."""
        cfg = RuntimeConfig(interface="eth0", dst="10.0.0.1")
        pool = _build_dest_pool(cfg)
        assert pool == ["10.0.0.1"]

    def test_build_dest_pool_with_subnet(self):
        """Test building pool from subnet."""
        cfg = RuntimeConfig(
            interface="eth0",
            dst="10.0.0.1",
            rand_dest=True,
            dest_subnet="192.168.1.0/30",
        )
        pool = _build_dest_pool(cfg)
        assert str(pool) == "192.168.1.0/30"
        assert pool.version == 4

    def test_build_dest_pool_empty(self):
        """Test building pool with no destination."""
        cfg = RuntimeConfig(interface="eth0", dst="")
        pool = _build_dest_pool(cfg)
        assert pool == []

    def test_build_dest_pool_rand_dest_without_subnet(self):
        """Test building pool with rand_dest but no subnet uses dst."""
        cfg = RuntimeConfig(
            interface="eth0",
            dst="10.0.0.5",
            rand_dest=True,
        )
        pool = _build_dest_pool(cfg)
        assert pool == ["10.0.0.5"]

    def test_build_dest_pool_ipv6_subnet(self):
        """Test building pool for IPv6 subnet."""
        cfg = RuntimeConfig(
            interface="eth0",
            dst="2001:db8::1",
            rand_dest=True,
            dest_subnet="2001:db8::/126",
            ip_version=6,
        )
        pool = _build_dest_pool(cfg)
        assert str(pool) == "2001:db8::/126"
        assert pool.version == 6


class TestSimulator:
    """Test Simulator class."""

    def test_simulator_initialization(self):
        """Test Simulator initializes correctly."""
        cfg = RuntimeConfig(interface="eth0", dst="10.0.0.1")
        sim = Simulator(cfg)

        assert sim.cfg == cfg
        assert sim.stats.sent == 0
        assert sim.stats.errors == 0
        assert sim.dest_mac_cache == {}
        assert sim.identities == []

    @patch("fluxgen.sender.get_interface_info")
    @patch("fluxgen.sender.generate_identities")
    @patch("fluxgen.sender.sendp")
    @patch("fluxgen.sender.getmacbyip")
    def test_simulator_dry_run(self, mock_getmac, mock_sendp, mock_gen_id, mock_iface, mock_sleep):
        """Test simulator in dry-run mode doesn't send packets."""
        # Mock interface info
        mock_iface.return_value = Mock(
            address=ipaddress.ip_interface("192.168.1.10/24"),
            mac="02:00:00:aa:bb:cc",
            gateway="192.168.1.1",
        )

        # Mock identities
        mock_gen_id.return_value = [
            Mock(ip=ipaddress.IPv4Address("192.168.1.100"), mac="02:00:00:aa:bb:01")
        ]

        # Mock MAC resolution
        mock_getmac.return_value = "aa:bb:cc:dd:ee:ff"

        cfg = RuntimeConfig(
            interface="eth0",
            dst="10.0.0.5",
            clients=1,
            count=1,
            dry_run=True,
            quiet=True,
        )

        sim = Simulator(cfg)
        stats = sim.run()

        # In dry run, packets aren't sent
        assert mock_sendp.call_count == 0
        assert stats.sent == 0

    @patch("fluxgen.sender.get_interface_info")
    @patch("fluxgen.sender.generate_identities")
    def test_simulator_no_dest_pool_error(self, mock_gen_id, mock_iface):
        """Test simulator raises error with no destination pool."""
        mock_iface.return_value = Mock(
            address=ipaddress.ip_interface("192.168.1.10/24"),
            mac="02:00:00:aa:bb:cc",
            gateway=None,
        )

        mock_gen_id.return_value = [
            Mock(ip=ipaddress.IPv4Address("192.168.1.100"), mac="02:00:00:aa:bb:01")
        ]

        cfg = RuntimeConfig(interface="eth0", dst="")  # No destination

        sim = Simulator(cfg)
        with pytest.raises(ValueError, match="No destination IPs"):
            sim.run()

    def test_simulator_resolve_dest_mac_cached(self):
        """Test MAC resolution uses cache."""
        cfg = RuntimeConfig(interface="eth0", dst="10.0.0.1")
        sim = Simulator(cfg)

        # Pre-populate cache
        sim.dest_mac_cache["10.0.0.1"] = "aa:bb:cc:dd:ee:ff"

        mac = sim._resolve_dest_mac("10.0.0.1")
        assert mac == "aa:bb:cc:dd:ee:ff"

    @patch("fluxgen.sender.getmacbyip")
    def test_simulator_resolve_dest_mac_fallback(self, mock_getmac):
        """Test MAC resolution falls back to broadcast."""
        mock_getmac.return_value = None

        cfg = RuntimeConfig(interface="eth0", dst="10.0.0.1", verbose=False)
        sim = Simulator(cfg)

        mac = sim._resolve_dest_mac("10.0.0.1")
        assert mac == "ff:ff:ff:ff:ff:ff"
        assert "10.0.0.1" in sim.dest_mac_cache

    @patch("fluxgen.sender.getmacbyip6")
    def test_simulator_resolve_dest_mac_fallback_ipv6(self, mock_getmac6):
        """Test MAC resolution falls back for IPv6."""
        mock_getmac6.return_value = None

        cfg = RuntimeConfig(interface="eth0", dst="2001:db8::1", verbose=False, ip_version=6)
        sim = Simulator(cfg)

        mac = sim._resolve_dest_mac("2001:db8::1")
        assert mac == "33:33:00:00:00:01"
        assert "2001:db8::1" in sim.dest_mac_cache

    @patch("fluxgen.sender.getmacbyip")
    def test_simulator_resolve_dest_mac_with_verbose(self, mock_getmac, capsys):
        """Test MAC resolution prints warning in verbose mode."""
        mock_getmac.return_value = None

        cfg = RuntimeConfig(interface="eth0", dst="10.0.0.1", verbose=True)
        sim = Simulator(cfg)

        mac = sim._resolve_dest_mac("10.0.0.1")
        assert mac == "ff:ff:ff:ff:ff:ff"

        captured = capsys.readouterr()
        assert "Warning" in captured.err
        assert "MAC resolution failed" in captured.err

    def test_simulator_report_loop_quiet(self):
        """Test report loop respects quiet mode."""
        cfg = RuntimeConfig(interface="eth0", dst="10.0.0.1", quiet=True)
        sim = Simulator(cfg)
        sim.stop_event.set()

        # Should return immediately in quiet mode
        sim._report_loop()
        # If it doesn't hang, test passes

    @patch("fluxgen.sender.get_interface_info")
    @patch("fluxgen.sender.generate_identities")
    @patch("fluxgen.sender.PcapWriter")
    def test_simulator_with_pcap_out(self, mock_pcap, mock_gen_id, mock_iface, mock_sleep):
        """Test simulator creates PcapWriter when pcap_out is specified."""
        mock_iface.return_value = Mock(
            address=ipaddress.ip_interface("192.168.1.10/24"),
            mac="02:00:00:aa:bb:cc",
            gateway=None,
        )

        mock_gen_id.return_value = [
            Mock(ip=ipaddress.IPv4Address("192.168.1.100"), mac="02:00:00:aa:bb:01")
        ]

        mock_pcap_instance = MagicMock()
        mock_pcap.return_value = mock_pcap_instance

        cfg = RuntimeConfig(
            interface="eth0",
            dst="10.0.0.5",
            clients=1,
            count=1,
            pcap_out="test.pcap",
            dry_run=True,
            quiet=True,
        )

        sim = Simulator(cfg)
        stats = sim.run()

        # Verify PcapWriter was created and closed
        mock_pcap.assert_called_once_with("test.pcap", append=True, sync=True)
        mock_pcap_instance.close.assert_called_once()

    @patch("fluxgen.sender.get_interface_info")
    @patch("fluxgen.sender.generate_identities")
    @patch("fluxgen.sender.build_frames")
    @patch("fluxgen.sender.sendp")
    @patch("fluxgen.sender.getmacbyip")
    @patch("fluxgen.sender.PcapWriter")
    def test_simulator_uses_external_pcap_writer(self, mock_pcap, mock_getmac, mock_sendp, mock_build, mock_gen_id, mock_iface):
        """External pcap writer should be honored and not replaced."""
        mock_iface.return_value = Mock(
            address=ipaddress.ip_interface("192.168.1.10/24"),
            mac="02:00:00:aa:bb:cc",
            gateway=None,
        )

        mock_gen_id.return_value = [
            Mock(ip=ipaddress.IPv4Address("192.168.1.100"), mac="02:00:00:aa:bb:01")
        ]

        mock_getmac.return_value = "aa:bb:cc:dd:ee:ff"
        fake_frame = MagicMock()
        mock_build.return_value = [fake_frame]

        external_writer = MagicMock()
        cfg = RuntimeConfig(
            interface="eth0",
            dst="10.0.0.5",
            clients=1,
            count=1,
            quiet=True,
        )

        sim = Simulator(cfg)
        stats = sim.run(pcap_writer=external_writer)

        # Should use provided writer and avoid creating a new one
        mock_pcap.assert_not_called()
        external_writer.write.assert_called_once_with(fake_frame)
        external_writer.close.assert_not_called()
        mock_sendp.assert_called_once()
        assert stats.sent == 1

    @patch("fluxgen.sender.get_interface_info")
    @patch("fluxgen.sender.generate_identities")
    @patch("fluxgen.sender.build_frames")
    @patch("fluxgen.sender.getmacbyip")
    def test_simulator_packet_craft_error(self, mock_getmac, mock_build, mock_gen_id, mock_iface, mock_sleep):
        """Test simulator handles packet crafting errors."""
        mock_iface.return_value = Mock(
            address=ipaddress.ip_interface("192.168.1.10/24"),
            mac="02:00:00:aa:bb:cc",
            gateway=None,
        )

        mock_gen_id.return_value = [
            Mock(ip=ipaddress.IPv4Address("192.168.1.100"), mac="02:00:00:aa:bb:01")
        ]

        mock_getmac.return_value = "aa:bb:cc:dd:ee:ff"

        # Make build_frames raise an error
        mock_build.side_effect = ValueError("Invalid frame config")

        cfg = RuntimeConfig(
            interface="eth0",
            dst="10.0.0.5",
            clients=1,
            count=1,
            verbose=False,
            quiet=True,
        )

        sim = Simulator(cfg)
        stats = sim.run()

        # Error should be caught and counted
        assert stats.errors >= 1
        assert stats.sent == 0

    @patch("fluxgen.sender.get_interface_info")
    @patch("fluxgen.sender.generate_identities")
    @patch("fluxgen.sender.build_frames")
    @patch("fluxgen.sender.sendp")
    @patch("fluxgen.sender.getmacbyip")
    def test_simulator_send_error(self, mock_getmac, mock_sendp, mock_build, mock_gen_id, mock_iface, mock_sleep):
        """Test simulator handles packet sending errors."""
        mock_iface.return_value = Mock(
            address=ipaddress.ip_interface("192.168.1.10/24"),
            mac="02:00:00:aa:bb:cc",
            gateway=None,
        )

        mock_gen_id.return_value = [
            Mock(ip=ipaddress.IPv4Address("192.168.1.100"), mac="02:00:00:aa:bb:01")
        ]

        mock_getmac.return_value = "aa:bb:cc:dd:ee:ff"

        # Mock build_frames to return a fake frame
        fake_frame = MagicMock()
        mock_build.return_value = [fake_frame]

        # Make sendp raise an error
        mock_sendp.side_effect = OSError("Permission denied")

        cfg = RuntimeConfig(
            interface="eth0",
            dst="10.0.0.5",
            clients=1,
            count=1,
            verbose=False,
            quiet=True,
        )

        sim = Simulator(cfg)
        stats = sim.run()

        # Error should be caught and counted
        assert stats.errors >= 1
        assert stats.sent == 0

    @patch("fluxgen.sender.get_interface_info")
    @patch("fluxgen.sender.generate_identities")
    @patch("fluxgen.sender.build_frames")
    @patch("fluxgen.sender.sendp")
    @patch("fluxgen.sender.getmacbyip")
    def test_simulator_verbose_errors(self, mock_getmac, mock_sendp, mock_build, mock_gen_id, mock_iface, capsys, mock_sleep):
        """Test simulator prints errors in verbose mode."""
        mock_iface.return_value = Mock(
            address=ipaddress.ip_interface("192.168.1.10/24"),
            mac="02:00:00:aa:bb:cc",
            gateway=None,
        )

        mock_gen_id.return_value = [
            Mock(ip=ipaddress.IPv4Address("192.168.1.100"), mac="02:00:00:aa:bb:01")
        ]

        mock_getmac.return_value = "aa:bb:cc:dd:ee:ff"
        mock_build.side_effect = ValueError("Test error")

        cfg = RuntimeConfig(
            interface="eth0",
            dst="10.0.0.5",
            clients=1,
            count=1,
            verbose=True,
            quiet=True,
        )

        sim = Simulator(cfg)
        stats = sim.run()

        captured = capsys.readouterr()
        assert "Failed to craft packet" in captured.err
        assert "Test error" in captured.err

    @patch("fluxgen.sender.get_interface_info")
    @patch("fluxgen.sender.generate_identities")
    @patch("fluxgen.sender.build_frames")
    @patch("fluxgen.sender.sendp")
    @patch("fluxgen.sender.getmacbyip")
    def test_simulator_count_limit(self, mock_getmac, mock_sendp, mock_build, mock_gen_id, mock_iface, mock_sleep):
        """Test simulator respects packet count limit."""
        mock_iface.return_value = Mock(
            address=ipaddress.ip_interface("192.168.1.10/24"),
            mac="02:00:00:aa:bb:cc",
            gateway=None,
        )

        mock_gen_id.return_value = [
            Mock(ip=ipaddress.IPv4Address("192.168.1.100"), mac="02:00:00:aa:bb:01")
        ]

        mock_getmac.return_value = "aa:bb:cc:dd:ee:ff"

        fake_frame = MagicMock()
        mock_build.return_value = [fake_frame]

        cfg = RuntimeConfig(
            interface="eth0",
            dst="10.0.0.5",
            clients=1,
            count=3,  # Send exactly 3 packets
            quiet=True,
        )

        sim = Simulator(cfg)
        stats = sim.run()

        # Should send exactly 3 packets
        assert stats.sent == 3

    @patch("fluxgen.sender.get_interface_info")
    @patch("fluxgen.sender.generate_identities")
    @patch("fluxgen.sender.build_frames")
    @patch("fluxgen.sender.sendp")
    @patch("fluxgen.sender.getmacbyip")
    def test_simulator_flood_mode(self, mock_getmac, mock_sendp, mock_build, mock_gen_id, mock_iface, mock_sleep):
        """Test simulator flood mode with no delay."""
        mock_iface.return_value = Mock(
            address=ipaddress.ip_interface("192.168.1.10/24"),
            mac="02:00:00:aa:bb:cc",
            gateway=None,
        )

        mock_gen_id.return_value = [
            Mock(ip=ipaddress.IPv4Address("192.168.1.100"), mac="02:00:00:aa:bb:01")
        ]

        mock_getmac.return_value = "aa:bb:cc:dd:ee:ff"

        fake_frame = MagicMock()
        mock_build.return_value = [fake_frame]

        cfg = RuntimeConfig(
            interface="eth0",
            dst="10.0.0.5",
            clients=1,
            count=5,
            flood=True,  # No delay between packets
            quiet=True,
        )

        sim = Simulator(cfg)
        stats = sim.run()

        assert stats.sent == 5

    @patch("fluxgen.sender.get_interface_info")
    @patch("fluxgen.sender.generate_identities")
    @patch("fluxgen.sender.build_frames")
    @patch("fluxgen.sender.sendp")
    @patch("fluxgen.sender.getmacbyip")
    def test_simulator_rand_source(self, mock_getmac, mock_sendp, mock_build, mock_gen_id, mock_iface, mock_sleep):
        """Test simulator randomizes source identity."""
        mock_iface.return_value = Mock(
            address=ipaddress.ip_interface("192.168.1.10/24"),
            mac="02:00:00:aa:bb:cc",
            gateway=None,
        )

        # Create multiple identities
        mock_gen_id.return_value = [
            Mock(ip=ipaddress.IPv4Address("192.168.1.100"), mac="02:00:00:aa:bb:01"),
            Mock(ip=ipaddress.IPv4Address("192.168.1.101"), mac="02:00:00:aa:bb:02"),
        ]

        mock_getmac.return_value = "aa:bb:cc:dd:ee:ff"

        fake_frame = MagicMock()
        mock_build.return_value = [fake_frame]

        cfg = RuntimeConfig(
            interface="eth0",
            dst="10.0.0.5",
            clients=2,
            count=2,
            rand_source=True,  # Randomize source
            quiet=True,
        )

        sim = Simulator(cfg)
        stats = sim.run()

        # Each client sends 2 packets = 4 total
        assert stats.sent == 4

    @patch("fluxgen.sender.get_interface_info")
    @patch("fluxgen.sender.generate_identities")
    @patch("fluxgen.sender.build_frames")
    @patch("fluxgen.sender.sendp")
    @patch("fluxgen.sender.getmacbyip")
    def test_simulator_rand_dest(self, mock_getmac, mock_sendp, mock_build, mock_gen_id, mock_iface, mock_sleep):
        """Test simulator randomizes destination."""
        mock_iface.return_value = Mock(
            address=ipaddress.ip_interface("192.168.1.10/24"),
            mac="02:00:00:aa:bb:cc",
            gateway=None,
        )

        mock_gen_id.return_value = [
            Mock(ip=ipaddress.IPv4Address("192.168.1.100"), mac="02:00:00:aa:bb:01")
        ]

        mock_getmac.return_value = "aa:bb:cc:dd:ee:ff"

        fake_frame = MagicMock()
        mock_build.return_value = [fake_frame]

        cfg = RuntimeConfig(
            interface="eth0",
            dst="10.0.0.5",
            dest_subnet="10.0.0.0/30",  # Small subnet with 2 hosts
            clients=1,
            count=2,
            rand_dest=True,  # Randomize destination
            quiet=True,
        )

        sim = Simulator(cfg)
        stats = sim.run()

        assert stats.sent == 2

    @patch("fluxgen.sender.get_interface_info")
    @patch("fluxgen.sender.generate_identities")
    @patch("fluxgen.sender.build_frames")
    @patch("fluxgen.sender.sendp")
    @patch("fluxgen.sender.getmacbyip")
    @patch("fluxgen.sender.PcapWriter")
    def test_simulator_pcap_write(self, mock_pcap, mock_getmac, mock_sendp, mock_build, mock_gen_id, mock_iface, mock_sleep):
        """Test simulator writes packets to pcap file."""
        mock_iface.return_value = Mock(
            address=ipaddress.ip_interface("192.168.1.10/24"),
            mac="02:00:00:aa:bb:cc",
            gateway=None,
        )

        mock_gen_id.return_value = [
            Mock(ip=ipaddress.IPv4Address("192.168.1.100"), mac="02:00:00:aa:bb:01")
        ]

        mock_getmac.return_value = "aa:bb:cc:dd:ee:ff"

        fake_frame = MagicMock()
        mock_build.return_value = [fake_frame]

        mock_pcap_instance = MagicMock()
        mock_pcap.return_value = mock_pcap_instance

        cfg = RuntimeConfig(
            interface="eth0",
            dst="10.0.0.5",
            clients=1,
            count=2,
            pcap_out="test.pcap",
            quiet=True,
        )

        sim = Simulator(cfg)
        stats = sim.run()

        # Verify packets were written to pcap
        assert mock_pcap_instance.write.call_count == 2
        assert stats.sent == 2

    @patch("fluxgen.sender.get_interface_info")
    @patch("fluxgen.sender.generate_identities")
    def test_simulator_with_gateway_exclusion(self, mock_gen_id, mock_iface, mock_sleep):
        """Test simulator excludes gateway IP from identity pool."""
        mock_iface.return_value = Mock(
            address=ipaddress.ip_interface("192.168.1.10/24"),
            mac="02:00:00:aa:bb:cc",
            gateway="192.168.1.1",
        )

        # Track what IPs were excluded
        excluded_ips = []

        def capture_excludes(count, network, exclude_ips, base_mac):
            nonlocal excluded_ips
            excluded_ips = list(exclude_ips)
            return [Mock(ip=ipaddress.IPv4Address("192.168.1.100"), mac="02:00:00:aa:bb:01")]

        mock_gen_id.side_effect = capture_excludes

        cfg = RuntimeConfig(
            interface="eth0",
            dst="10.0.0.5",
            clients=1,
            count=1,
            dry_run=True,
            quiet=True,
        )

        sim = Simulator(cfg)
        stats = sim.run()

        # Verify both interface IP and gateway were excluded
        assert "192.168.1.10" in excluded_ips
        assert "192.168.1.1" in excluded_ips

    @patch("fluxgen.sender.get_interface_info")
    @patch("fluxgen.sender.generate_identities")
    def test_simulator_custom_subnet_pool(self, mock_gen_id, mock_iface, mock_sleep):
        """Test simulator uses custom subnet pool."""
        mock_iface.return_value = Mock(
            address=ipaddress.ip_interface("192.168.1.10/24"),
            mac="02:00:00:aa:bb:cc",
            gateway=None,
        )

        # Track what network was used
        used_network = None

        def capture_network(count, network, exclude_ips, base_mac):
            nonlocal used_network
            used_network = network
            return [Mock(ip=ipaddress.IPv4Address("10.0.0.100"), mac="02:00:00:aa:bb:01")]

        mock_gen_id.side_effect = capture_network

        cfg = RuntimeConfig(
            interface="eth0",
            dst="10.0.0.5",
            subnet_pool="10.0.0.0/24",  # Custom subnet
            clients=1,
            count=1,
            dry_run=True,
            quiet=True,
        )

        sim = Simulator(cfg)
        stats = sim.run()

        # Verify custom subnet was used
        assert used_network == ipaddress.ip_network("10.0.0.0/24")

    def test_simulator_report_loop_with_output(self, capsys):
        """Test report loop prints stats periodically."""
        cfg = RuntimeConfig(interface="eth0", dst="10.0.0.1", quiet=False)
        sim = Simulator(cfg)
        sim.stats.bump_sent(5)
        sim.stats.bump_error(2)

        # Mock stop_event.wait to return False first (print), then True (stop)
        call_count = 0
        def mock_wait(timeout=None):
            nonlocal call_count
            call_count += 1
            return call_count > 1  # False on first call, True on second

        with patch.object(sim.stop_event, 'wait', side_effect=mock_wait):
            sim._report_loop()

        captured = capsys.readouterr()
        # Should have printed stats
        assert "sent=5" in captured.out
        assert "errors=2" in captured.out

    @patch("fluxgen.sender.get_interface_info")
    @patch("fluxgen.sender.generate_identities")
    @patch("fluxgen.sender.build_frames")
    @patch("fluxgen.sender.sendp")
    @patch("fluxgen.sender.getmacbyip")
    def test_simulator_send_error_verbose(self, mock_getmac, mock_sendp, mock_build, mock_gen_id, mock_iface, capsys, mock_sleep):
        """Test simulator prints send errors in verbose mode."""
        mock_iface.return_value = Mock(
            address=ipaddress.ip_interface("192.168.1.10/24"),
            mac="02:00:00:aa:bb:cc",
            gateway=None,
        )

        mock_gen_id.return_value = [
            Mock(ip=ipaddress.IPv4Address("192.168.1.100"), mac="02:00:00:aa:bb:01")
        ]

        mock_getmac.return_value = "aa:bb:cc:dd:ee:ff"

        fake_frame = MagicMock()
        mock_build.return_value = [fake_frame]

        # Make sendp raise error
        mock_sendp.side_effect = OSError("Network unreachable")

        cfg = RuntimeConfig(
            interface="eth0",
            dst="10.0.0.5",
            clients=1,
            count=1,
            verbose=True,
            quiet=True,
        )

        sim = Simulator(cfg)
        stats = sim.run()

        captured = capsys.readouterr()
        assert "Send error for 10.0.0.5" in captured.err
        assert "Network unreachable" in captured.err
        assert stats.errors >= 1

    @patch("fluxgen.sender.get_interface_info")
    @patch("fluxgen.sender.generate_identities")
    @patch("fluxgen.sender.build_frames")
    @patch("fluxgen.sender.getmacbyip")
    def test_simulator_packet_craft_error_with_count(self, mock_getmac, mock_build, mock_gen_id, mock_iface, mock_sleep):
        """Test that count limit works even with packet craft errors."""
        mock_iface.return_value = Mock(
            address=ipaddress.ip_interface("192.168.1.10/24"),
            mac="02:00:00:aa:bb:cc",
            gateway=None,
        )

        mock_gen_id.return_value = [
            Mock(ip=ipaddress.IPv4Address("192.168.1.100"), mac="02:00:00:aa:bb:01")
        ]

        mock_getmac.return_value = "aa:bb:cc:dd:ee:ff"

        # Always raise error
        mock_build.side_effect = ValueError("Always fails")

        cfg = RuntimeConfig(
            interface="eth0",
            dst="10.0.0.5",
            clients=1,
            count=5,  # Should stop after 5 attempts even with errors
            verbose=False,
            quiet=True,
        )

        sim = Simulator(cfg)
        stats = sim.run()

        # Should have tried 5 times and failed each time
        assert stats.errors == 5
        assert stats.sent == 0

    @patch("fluxgen.sender.get_interface_info")
    @patch("fluxgen.sender.generate_identities")
    @patch("fluxgen.sender.build_frames")
    @patch("fluxgen.sender.sendp")
    @patch("fluxgen.sender.getmacbyip")
    def test_simulator_non_flood_uses_sleep(self, mock_getmac, mock_sendp, mock_build, mock_gen_id, mock_iface, mock_sleep):
        """Test simulator uses sleep interval in non-flood mode."""
        mock_iface.return_value = Mock(
            address=ipaddress.ip_interface("192.168.1.10/24"),
            mac="02:00:00:aa:bb:cc",
            gateway=None,
        )

        mock_gen_id.return_value = [
            Mock(ip=ipaddress.IPv4Address("192.168.1.100"), mac="02:00:00:aa:bb:01")
        ]

        mock_getmac.return_value = "aa:bb:cc:dd:ee:ff"

        fake_frame = MagicMock()
        mock_build.return_value = [fake_frame]

        cfg = RuntimeConfig(
            interface="eth0",
            dst="10.0.0.5",
            clients=1,
            count=3,
            interval=0.5,  # Custom interval
            flood=False,  # Non-flood mode
            quiet=True,
        )

        sim = Simulator(cfg)
        stats = sim.run()

        # Should have called sleep with interval after each send except last
        assert mock_sleep.call_count == 2  # count-1 times
        mock_sleep.assert_called_with(0.5)
        assert stats.sent == 3
