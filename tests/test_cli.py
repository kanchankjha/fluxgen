"""Unit tests for CLI module."""

import pytest
from unittest.mock import patch, MagicMock
from fluxgen.cli import main, _parse_args
from fluxgen.config import RuntimeConfig


class TestParseArgs:
    """Test command-line argument parsing."""

    def test_parse_args_minimal(self):
        """Test parsing minimal required arguments."""
        args = _parse_args(["--interface", "eth0", "--dst", "10.0.0.1"])
        assert args.interface == "eth0"
        assert args.dst == "10.0.0.1"

    def test_parse_args_all_options(self):
        """Test parsing all available arguments."""
        argv = [
            "--interface", "eth0",
            "--dst", "10.0.0.5",
            "--clients", "10",
            "--proto", "tcp",
            "--dport", "80",
            "--sport", "12345",
            "--flags", "S",
            "--interval", "0.05",
            "--count", "100",
            "--ttl", "32",
            "--verbose",
            "--quiet",
            "--data-size", "16",
            "--frag-mode", "random",
            "--ip-version", "6",
        ]
        args = _parse_args(argv)
        assert args.interface == "eth0"
        assert args.dst == "10.0.0.5"
        assert args.clients == 10
        assert args.proto == "tcp"
        assert args.dport == 80
        assert args.sport == 12345
        assert args.flags == "S"
        assert args.interval == 0.05
        assert args.count == 100
        assert args.ttl == 32
        assert args.verbose is True
        assert args.quiet is True
        assert args.data_size == 16
        assert args.frag_mode == "random"
        assert args.ip_version == "6"

    def test_parse_args_protocol_choices(self):
        """Test all protocol choices are accepted."""
        protocols = ["tcp", "udp", "icmp", "igmp", "gre", "esp", "ah", "sctp"]
        for proto in protocols:
            args = _parse_args(["--interface", "eth0", "--dst", "10.0.0.1", "--proto", proto])
            assert args.proto == proto

    def test_parse_args_invalid_protocol(self):
        """Test invalid protocol is rejected."""
        with pytest.raises(SystemExit):
            _parse_args(["--interface", "eth0", "--dst", "10.0.0.1", "--proto", "invalid"])

    def test_parse_args_config_file(self):
        """Test parsing with config file argument."""
        args = _parse_args(["--config", "config.yaml", "--interface", "eth0", "--dst", "10.0.0.1"])
        assert args.config == "config.yaml"

    def test_parse_args_boolean_flags(self):
        """Test boolean flag arguments."""
        args = _parse_args([
            "--interface", "eth0",
            "--dst", "10.0.0.1",
            "--flood",
            "--rand-source",
            "--rand-dest",
            "--dry-run",
            "--verbose",
            "--quiet",
            "--frag",
        ])
        assert args.flood is True
        assert args.rand_source is True
        assert args.rand_dest is True
        assert args.dry_run is True
        assert args.verbose is True
        assert args.quiet is True
        assert args.frag is True

    def test_parse_args_payload_options(self):
        """Test payload-related arguments."""
        args = _parse_args([
            "--interface", "eth0",
            "--dst", "10.0.0.1",
            "--payload", "deadbeef",
            "--payload-hex",
            "--data-size", "32",
        ])
        assert args.payload == "deadbeef"
        assert args.payload_hex is True
        assert args.data_size == 32

    def test_parse_args_subnet_options(self):
        """Test subnet-related arguments."""
        args = _parse_args([
            "--interface", "eth0",
            "--dst", "10.0.0.1",
            "--subnet-pool", "192.168.1.0/24",
            "--dest-subnet", "10.0.0.0/24",
        ])
        assert args.subnet_pool == "192.168.1.0/24"
        assert args.dest_subnet == "10.0.0.0/24"

    def test_parse_args_icmp_options(self):
        """Test ICMP-related arguments."""
        args = _parse_args([
            "--interface", "eth0",
            "--dst", "10.0.0.1",
            "--proto", "icmp",
            "--icmp-type", "8",
            "--icmp-code", "0",
        ])
        assert args.icmp_type == 8
        assert args.icmp_code == 0

    def test_parse_args_fragmentation_options(self):
        """Test fragmentation arguments."""
        args = _parse_args([
            "--interface", "eth0",
            "--dst", "10.0.0.1",
            "--frag",
            "--frag-size", "500",
            "--frag-mode", "fixed",
        ])
        assert args.frag is True
        assert args.frag_size == 500
        assert args.frag_mode == "fixed"


class TestMain:
    """Test main entry point."""

    @patch("fluxgen.cli.Simulator")
    @patch("fluxgen.cli.build_runtime_config")
    def test_main_basic_execution(self, mock_build_config, mock_simulator):
        """Test main function with basic arguments."""
        # Mock configuration
        mock_config = RuntimeConfig(interface="eth0", dst="10.0.0.1")
        mock_build_config.return_value = mock_config

        # Mock simulator
        mock_sim_instance = MagicMock()
        mock_stats = MagicMock()
        mock_stats.sent = 100
        mock_stats.errors = 0
        mock_sim_instance.run.return_value = mock_stats
        mock_simulator.return_value = mock_sim_instance

        # Run main
        result = main(["--interface", "eth0", "--dst", "10.0.0.1"])

        assert result == 0
        mock_simulator.assert_called_once_with(mock_config)
        mock_sim_instance.run.assert_called_once()

    @patch("fluxgen.cli.load_config_file")
    @patch("fluxgen.cli.Simulator")
    @patch("fluxgen.cli.build_runtime_config")
    def test_main_with_config_file(self, mock_build_config, mock_simulator, mock_load_config):
        """Test main function with config file."""
        # Mock file config
        mock_load_config.return_value = {
            "interface": "eth0",
            "dst": "10.0.0.1",
            "clients": 5,
        }

        # Mock runtime config
        mock_config = RuntimeConfig(interface="eth0", dst="10.0.0.1", clients=5)
        mock_build_config.return_value = mock_config

        # Mock simulator
        mock_sim_instance = MagicMock()
        mock_stats = MagicMock()
        mock_stats.sent = 500
        mock_stats.errors = 5
        mock_sim_instance.run.return_value = mock_stats
        mock_simulator.return_value = mock_sim_instance

        # Run main
        result = main(["--config", "test.yaml"])

        assert result == 0
        mock_load_config.assert_called_once_with("test.yaml")

    @patch("fluxgen.cli.merge_config")
    @patch("fluxgen.cli.load_config_file")
    @patch("fluxgen.cli.Simulator")
    @patch("fluxgen.cli.build_runtime_config")
    def test_main_config_file_and_cli_merge(self, mock_build_config, mock_simulator,
                                            mock_load_config, mock_merge):
        """Test main merges config file and CLI arguments."""
        # Mock file config
        file_config = {"interface": "eth0", "clients": 5}
        mock_load_config.return_value = file_config

        # Mock merge
        merged_config = {"interface": "eth0", "dst": "10.0.0.1", "clients": 10}
        mock_merge.return_value = merged_config

        # Mock runtime config
        mock_config = RuntimeConfig(interface="eth0", dst="10.0.0.1", clients=10)
        mock_build_config.return_value = mock_config

        # Mock simulator
        mock_sim_instance = MagicMock()
        mock_stats = MagicMock()
        mock_stats.sent = 1000
        mock_stats.errors = 0
        mock_sim_instance.run.return_value = mock_stats
        mock_simulator.return_value = mock_sim_instance

        # Run main
        result = main(["--config", "test.yaml", "--dst", "10.0.0.1", "--clients", "10"])

        assert result == 0
        mock_merge.assert_called_once()
        # Verify file config was passed to merge
        call_args = mock_merge.call_args[0]
        assert call_args[0] == file_config
