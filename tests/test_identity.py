"""Unit tests for identity module."""

import ipaddress
import pytest
from fluxgen.identity import Identity, generate_identities, _mac_seed, _mac_from_seed


class TestIdentity:
    """Test Identity dataclass."""

    def test_identity_creation(self):
        """Test creating an Identity instance."""
        ip = ipaddress.IPv4Address("192.168.1.10")
        mac = "02:00:00:aa:bb:cc"
        identity = Identity(ip=ip, mac=mac)
        assert identity.ip == ip
        assert identity.mac == mac

    def test_identity_creation_ipv6(self):
        """Test creating Identity with IPv6."""
        ip = ipaddress.IPv6Address("2001:db8::1")
        mac = "02:00:00:aa:bb:cc"
        identity = Identity(ip=ip, mac=mac)
        assert identity.ip == ip


class TestMacSeed:
    """Test MAC seed generation."""

    def test_mac_seed_from_base_mac(self):
        """Test generating seed from base MAC address."""
        base_mac = "aa:bb:cc:dd:ee:ff"
        seed = _mac_seed(base_mac)
        assert seed == [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]

    def test_mac_seed_random_generation(self):
        """Test generating random MAC seed."""
        seed = _mac_seed(None)
        assert len(seed) == 6
        # Check locally administered prefix
        assert seed[0] == 0x02
        assert seed[1] == 0x00
        assert seed[2] == 0x00
        # Last byte should be 0x00
        assert seed[5] == 0x00

    def test_mac_seed_invalid_format(self):
        """Test invalid MAC address format raises error."""
        with pytest.raises(ValueError, match="Invalid MAC address"):
            _mac_seed("invalid")

        with pytest.raises(ValueError, match="Invalid MAC address"):
            _mac_seed("aa:bb:cc:dd:ee")  # Too few octets

        with pytest.raises(ValueError, match="Invalid MAC address"):
            _mac_seed("zz:bb:cc:dd:ee:ff")  # Invalid hex


class TestMacFromSeed:
    """Test MAC address generation from seed."""

    def test_mac_from_seed_sequential(self):
        """Test generating sequential MAC addresses."""
        seed = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00]

        mac0 = _mac_from_seed(seed, 0)
        mac1 = _mac_from_seed(seed, 1)
        mac2 = _mac_from_seed(seed, 2)

        assert mac0 == "02:00:00:00:00:01"
        assert mac1 == "02:00:00:00:00:02"
        assert mac2 == "02:00:00:00:00:03"

    def test_mac_from_seed_large_index(self):
        """Test MAC generation with large index."""
        seed = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00]
        mac = _mac_from_seed(seed, 255)
        # Should be 256 (0x100) in hex, but wraps in the lower bytes
        assert len(mac.split(":")) == 6

    def test_mac_from_seed_custom_base(self):
        """Test MAC generation from custom base."""
        seed = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]
        mac = _mac_from_seed(seed, 0)
        # Should increment by 1
        assert mac == "aa:bb:cc:dd:ef:00"


class TestGenerateIdentities:
    """Test identity pool generation."""

    def test_generate_identities_basic(self):
        """Test generating basic identity pool."""
        network = ipaddress.ip_network("192.168.1.0/24")
        exclude_ips = ["192.168.1.1", "192.168.1.254"]

        identities = generate_identities(
            count=5,
            network=network,
            exclude_ips=exclude_ips,
        )

        assert len(identities) == 5
        for identity in identities:
            assert isinstance(identity.ip, ipaddress.IPv4Address)
            assert identity.ip in network
            assert str(identity.ip) not in exclude_ips
            assert isinstance(identity.mac, str)
            assert len(identity.mac.split(":")) == 6

    def test_generate_identities_with_base_mac(self):
        """Test generating identities with custom base MAC."""
        network = ipaddress.ip_network("10.0.0.0/28")
        base_mac = "02:11:22:33:44:00"

        identities = generate_identities(
            count=3,
            network=network,
            exclude_ips=[],
            base_mac=base_mac,
        )

        assert len(identities) == 3
        # All MACs should start with base prefix
        for identity in identities:
            assert identity.mac.startswith("02:11:22:33:44")

    def test_generate_identities_insufficient_ips(self):
        """Test generating more identities than available IPs."""
        network = ipaddress.ip_network("192.168.1.0/30")  # Only 2 usable hosts

        with pytest.raises(ValueError, match="Not enough usable IPs"):
            generate_identities(
                count=10,
                network=network,
                exclude_ips=[],
            )

    def test_generate_identities_all_excluded(self):
        """Test when all IPs are excluded."""
        network = ipaddress.ip_network("192.168.1.0/30")
        hosts = list(network.hosts())
        exclude_ips = [str(ip) for ip in hosts]

        with pytest.raises(ValueError, match="Not enough usable IPs"):
            generate_identities(
                count=1,
                network=network,
                exclude_ips=exclude_ips,
            )

    def test_generate_identities_unique_ips(self):
        """Test that generated identities have unique IPs."""
        network = ipaddress.ip_network("172.16.0.0/24")

        identities = generate_identities(
            count=10,
            network=network,
            exclude_ips=[],
        )

        ips = [str(identity.ip) for identity in identities]
        assert len(ips) == len(set(ips))  # All unique

    def test_generate_identities_unique_macs(self):
        """Test that generated identities have unique MACs."""
        network = ipaddress.ip_network("172.16.0.0/24")

        identities = generate_identities(
            count=10,
            network=network,
            exclude_ips=[],
        )

        macs = [identity.mac for identity in identities]
        assert len(macs) == len(set(macs))  # All unique

    def test_generate_identities_large_pool(self):
        """Test generating large identity pool."""
        network = ipaddress.ip_network("10.0.0.0/22")  # 1024 hosts

        identities = generate_identities(
            count=100,
            network=network,
            exclude_ips=[],
        )

        assert len(identities) == 100
        # Verify all are in network
        for identity in identities:
            assert identity.ip in network

    def test_generate_identities_ipv6(self):
        """Test generating identities in IPv6 subnet without full enumeration."""
        network = ipaddress.ip_network("2001:db8::/120")  # 256 addresses
        identities = generate_identities(
            count=5,
            network=network,
            exclude_ips=["2001:db8::"],
        )
        assert len(identities) == 5
        for identity in identities:
            assert isinstance(identity.ip, ipaddress.IPv6Address)
            assert identity.ip in network
            assert str(identity.ip) != "2001:db8::"

    def test_generate_identities_ipv6_insufficient(self):
        """Test not enough IPv6 addresses raises error."""
        network = ipaddress.ip_network("2001:db8::/128")
        with pytest.raises(ValueError, match="Not enough usable IPs"):
            generate_identities(
                count=2,
                network=network,
                exclude_ips=[],
            )
