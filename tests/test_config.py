"""Unit tests for config module."""

import json
import pathlib
import pytest
import tempfile
from fluxgen.config import (
    RuntimeConfig,
    build_runtime_config,
    load_config_file,
    merge_config,
)


class TestRuntimeConfig:
    """Test RuntimeConfig dataclass."""

    def test_default_values(self):
        """Test RuntimeConfig with minimal required fields."""
        cfg = RuntimeConfig(interface="eth0", dst="10.0.0.1")
        assert cfg.interface == "eth0"
        assert cfg.dst == "10.0.0.1"
        assert cfg.clients == 1
        assert cfg.proto == "tcp"
        assert cfg.flags == "S"
        assert cfg.ttl == 64
        assert cfg.interval == 0.1

    def test_custom_values(self):
        """Test RuntimeConfig with custom values."""
        cfg = RuntimeConfig(
            interface="eth1",
            dst="192.168.1.1",
            clients=10,
            proto="udp",
            dport=8080,
            flood=True,
        )
        assert cfg.clients == 10
        assert cfg.proto == "udp"
        assert cfg.dport == 8080
        assert cfg.flood is True


class TestLoadConfigFile:
    """Test configuration file loading."""

    def test_load_json_config(self):
        """Test loading JSON configuration file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"interface": "eth0", "dst": "10.0.0.1", "clients": 5}, f)
            temp_path = f.name

        try:
            data = load_config_file(temp_path)
            assert data["interface"] == "eth0"
            assert data["dst"] == "10.0.0.1"
            assert data["clients"] == 5
        finally:
            pathlib.Path(temp_path).unlink()

    def test_load_yaml_config(self):
        """Test loading YAML configuration file."""
        yaml_content = """
interface: eth0
dst: 10.0.0.1
clients: 5
proto: tcp
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            temp_path = f.name

        try:
            data = load_config_file(temp_path)
            assert data["interface"] == "eth0"
            assert data["dst"] == "10.0.0.1"
            assert data["clients"] == 5
            assert data["proto"] == "tcp"
        finally:
            pathlib.Path(temp_path).unlink()

    def test_missing_file(self):
        """Test loading nonexistent file raises error."""
        with pytest.raises(FileNotFoundError):
            load_config_file("/nonexistent/file.json")

    def test_invalid_json(self):
        """Test loading invalid JSON raises error."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{invalid json")
            temp_path = f.name

        try:
            with pytest.raises(json.JSONDecodeError):
                load_config_file(temp_path)
        finally:
            pathlib.Path(temp_path).unlink()


class TestMergeConfig:
    """Test configuration merging."""

    def test_merge_empty_override(self):
        """Test merging with empty override keeps base values."""
        base = {"interface": "eth0", "dst": "10.0.0.1", "clients": 5}
        override = {}
        result = merge_config(base, override)
        assert result == base

    def test_merge_with_override(self):
        """Test merging overrides base values."""
        base = {"interface": "eth0", "dst": "10.0.0.1", "clients": 5}
        override = {"clients": 10, "proto": "udp"}
        result = merge_config(base, override)
        assert result["interface"] == "eth0"
        assert result["dst"] == "10.0.0.1"
        assert result["clients"] == 10
        assert result["proto"] == "udp"

    def test_merge_ignores_none_values(self):
        """Test merging ignores None values in override."""
        base = {"interface": "eth0", "clients": 5}
        override = {"clients": None, "proto": "udp"}
        result = merge_config(base, override)
        assert result["clients"] == 5  # Not overridden
        assert result["proto"] == "udp"


class TestBuildRuntimeConfig:
    """Test building RuntimeConfig from dictionary."""

    def test_minimal_config(self):
        """Test building config with minimal required fields."""
        data = {"interface": "eth0", "dst": "10.0.0.1"}
        cfg = build_runtime_config(data)
        assert cfg.interface == "eth0"
        assert cfg.dst == "10.0.0.1"
        assert cfg.clients == 1
        assert cfg.proto == "tcp"
        assert cfg.ip_version == 4

    def test_missing_interface(self):
        """Test building config without interface raises error."""
        data = {"dst": "10.0.0.1"}
        with pytest.raises(ValueError, match="Missing required option: interface"):
            build_runtime_config(data)

    def test_missing_dst_and_dest_subnet(self):
        """Test building config without dst or dest_subnet raises error."""
        data = {"interface": "eth0"}
        with pytest.raises(ValueError, match="Provide dst or dest_subnet"):
            build_runtime_config(data)

    def test_dest_subnet_only(self):
        """Test building config with dest_subnet instead of dst."""
        data = {"interface": "eth0", "dest_subnet": "10.0.0.0/24"}
        cfg = build_runtime_config(data)
        assert cfg.interface == "eth0"
        assert cfg.dest_subnet == "10.0.0.0/24"

    def test_all_protocols(self):
        """Test all supported protocols."""
        protocols = ["tcp", "udp", "icmp", "igmp", "gre", "esp", "ah", "sctp"]
        for proto in protocols:
            data = {"interface": "eth0", "dst": "10.0.0.1", "proto": proto}
            cfg = build_runtime_config(data)
            assert cfg.proto == proto

    def test_invalid_protocol(self):
        """Test invalid protocol raises error."""
        data = {"interface": "eth0", "dst": "10.0.0.1", "proto": "invalid"}
        with pytest.raises(ValueError, match="Invalid protocol"):
            build_runtime_config(data)

    def test_port_validation(self):
        """Test port number validation."""
        # Valid ports
        data = {"interface": "eth0", "dst": "10.0.0.1", "dport": 80, "sport": 12345}
        cfg = build_runtime_config(data)
        assert cfg.dport == 80
        assert cfg.sport == 12345

        # Invalid destination port
        data = {"interface": "eth0", "dst": "10.0.0.1", "dport": 70000}
        with pytest.raises(ValueError, match="Invalid destination port"):
            build_runtime_config(data)

        # Invalid source port
        data = {"interface": "eth0", "dst": "10.0.0.1", "sport": -1}
        with pytest.raises(ValueError, match="Invalid source port"):
            build_runtime_config(data)

    def test_tcp_flags_validation(self):
        """Test TCP flags validation."""
        # Valid flags
        valid_flags = ["S", "SA", "SAFPRU", "s", "sa"]
        for flags in valid_flags:
            data = {"interface": "eth0", "dst": "10.0.0.1", "flags": flags}
            cfg = build_runtime_config(data)
            assert cfg.flags == flags

        # Invalid flags
        data = {"interface": "eth0", "dst": "10.0.0.1", "flags": "XYZ"}
        with pytest.raises(ValueError, match="Invalid TCP flags"):
            build_runtime_config(data)

    def test_icmp_validation(self):
        """Test ICMP type and code validation."""
        # Valid ICMP
        data = {"interface": "eth0", "dst": "10.0.0.1", "icmp_type": 8, "icmp_code": 0}
        cfg = build_runtime_config(data)
        assert cfg.icmp_type == 8
        assert cfg.icmp_code == 0

        # Invalid ICMP type
        data = {"interface": "eth0", "dst": "10.0.0.1", "icmp_type": 300}
        with pytest.raises(ValueError, match="Invalid ICMP type"):
            build_runtime_config(data)

        # Invalid ICMP code
        data = {"interface": "eth0", "dst": "10.0.0.1", "icmp_code": 300}
        with pytest.raises(ValueError, match="Invalid ICMP code"):
            build_runtime_config(data)

    def test_boolean_flags(self):
        """Test boolean flag handling."""
        data = {
            "interface": "eth0",
            "dst": "10.0.0.1",
            "flood": True,
            "rand_source": True,
            "dry_run": True,
            "verbose": True,
            "quiet": True,
        }
        cfg = build_runtime_config(data)
        assert cfg.flood is True
        assert cfg.rand_source is True
        assert cfg.dry_run is True
        assert cfg.verbose is True
        assert cfg.quiet is True
        assert cfg.ip_version == 4

    def test_data_size_and_fragmentation_validation(self):
        """Test validation of data_size and frag_mode."""
        data = {"interface": "eth0", "dst": "10.0.0.1", "data_size": 128}
        cfg = build_runtime_config(data)
        assert cfg.data_size == 128

        for bad_size in (-1, 0):
            data_negative = {"interface": "eth0", "dst": "10.0.0.1", "data_size": bad_size}
            with pytest.raises(ValueError, match="data_size"):
                build_runtime_config(data_negative)

        data_conflict = {"interface": "eth0", "dst": "10.0.0.1", "payload": "a", "data_size": 10}
        with pytest.raises(ValueError, match="payload or data_size"):
            build_runtime_config(data_conflict)

        data_frag_mode = {"interface": "eth0", "dst": "10.0.0.1", "frag_mode": "random"}
        cfg = build_runtime_config(data_frag_mode)
        assert cfg.frag_mode == "random"

        data_bad_frag_mode = {"interface": "eth0", "dst": "10.0.0.1", "frag_mode": "weird"}
        with pytest.raises(ValueError, match="frag_mode"):
            build_runtime_config(data_bad_frag_mode)

    def test_ip_version_resolution(self):
        """Test ip_version detection and overrides."""
        data_v6 = {"interface": "eth0", "dst": "2001:db8::1"}
        cfg = build_runtime_config(data_v6)
        assert cfg.ip_version == 6

        data_force_v4 = {"interface": "eth0", "dst": "10.0.0.1", "ip_version": "4"}
        cfg = build_runtime_config(data_force_v4)
        assert cfg.ip_version == 4

        data_mismatch = {"interface": "eth0", "dst": "2001:db8::1", "ip_version": 4}
        with pytest.raises(ValueError, match="ip_version"):
            build_runtime_config(data_mismatch)

        data_auto_default = {"interface": "eth0", "dst": "example.com"}
        cfg = build_runtime_config(data_auto_default)
        assert cfg.ip_version == 4


class TestConfigEdgeCases:
    """Test edge cases and error conditions."""

    def test_load_config_file_non_dict(self):
        """Test loading config file that's not a dict raises error."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(["not", "a", "dict"], f)  # Array instead of dict
            temp_path = f.name

        try:
            with pytest.raises(ValueError, match="must define a mapping"):
                load_config_file(temp_path)
        finally:
            pathlib.Path(temp_path).unlink()

    def test_maybe_int_helper(self):
        """Test _maybe_int handles various types."""
        from fluxgen.config import _maybe_int

        assert _maybe_int(None) is None
        assert _maybe_int(42) == 42
        assert _maybe_int("123") == 123
        assert _maybe_int("not a number") is None
        assert _maybe_int([1, 2, 3]) is None
        assert _maybe_int({"key": "value"}) is None
