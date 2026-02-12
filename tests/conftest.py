"""Pytest configuration and shared fixtures."""

import ipaddress
import pytest
from fluxgen.config import RuntimeConfig
from fluxgen.identity import Identity


@pytest.fixture
def basic_config():
    """Basic runtime configuration for testing."""
    return RuntimeConfig(
        interface="eth0",
        dst="10.0.0.5",
        clients=5,
        proto="tcp",
        dport=80,
        sport=12345,
        flags="S",
        ttl=64,
        tos=0,
        interval=0.1,
        count=10,
    )


@pytest.fixture
def test_identity():
    """Test identity with IP and MAC."""
    return Identity(
        ip=ipaddress.IPv4Address("192.168.1.100"),
        mac="02:00:00:aa:bb:cc",
    )


@pytest.fixture
def sample_network():
    """Sample IPv4 network for testing."""
    return ipaddress.ip_network("192.168.1.0/24")
