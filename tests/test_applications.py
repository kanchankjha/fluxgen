"""Tests for application-shaped traffic profiles."""

import ipaddress

import pytest
from scapy.all import Ether, IP, Raw, TCP, UDP

from fluxgen.applications import (
    APPLICATION_NAMES,
    APPLICATION_PROFILES,
    ApplicationFlow,
    application_profile_count,
    build_application_payload,
    normalize_application_names,
    select_application_profile,
)
from fluxgen.config import RuntimeConfig
from fluxgen.identity import Identity
from fluxgen.packet_builder import build_frames


class TestApplicationCatalog:
    def test_catalog_contains_100_unique_profiles(self):
        assert application_profile_count() == 100
        assert len(APPLICATION_NAMES) == 100
        assert len(set(APPLICATION_NAMES)) == 100
        assert set(APPLICATION_NAMES) == set(APPLICATION_PROFILES)

    def test_every_profile_has_valid_flows(self):
        for name in APPLICATION_NAMES:
            profile = APPLICATION_PROFILES[name]
            assert profile.name == name
            assert profile.category
            assert profile.flows
            for flow in profile.flows:
                assert isinstance(flow, ApplicationFlow)
                assert flow.transport in {"tcp", "udp"}
                assert flow.ports
                assert all(0 <= port <= 65535 for port in flow.ports)
                assert 0 < flow.payload_min <= flow.payload_max
                assert flow.weight > 0

    def test_every_profile_flow_builds_a_valid_frame(self):
        cfg = RuntimeConfig(interface="eth0", dst="10.0.0.5")
        identity = Identity(
            ip=ipaddress.IPv4Address("192.168.1.100"),
            mac="02:00:00:aa:bb:cc",
        )

        for profile in APPLICATION_PROFILES.values():
            packet_index = 0
            for flow in profile.flows:
                for _ in range(flow.weight):
                    frame = build_frames(
                        cfg,
                        identity,
                        "10.0.0.5",
                        "aa:bb:cc:dd:ee:ff",
                        application_profile=profile,
                        application_index=packet_index,
                        client_index=3,
                    )[0]
                    assert frame.haslayer(Ether)
                    assert frame.haslayer(IP)
                    assert frame.haslayer(Raw)
                    assert frame.haslayer(TCP) or frame.haslayer(UDP)
                    assert flow.payload_min <= len(frame[Raw].load) <= flow.payload_max
                    packet_index += 1

    def test_requested_profiles_rotate_deterministically(self):
        names = normalize_application_names("webex, outlook")
        observed = [
            select_application_profile(names, client_index=0, packet_index=index).name
            for index in range(4)
        ]
        assert observed == ["webex", "outlook", "webex", "outlook"]

    def test_all_rotates_through_catalog(self):
        names = normalize_application_names("all")
        observed = [
            select_application_profile(names, client_index=0, packet_index=index).name
            for index in range(100)
        ]
        assert tuple(observed) == APPLICATION_NAMES

    @pytest.mark.parametrize("value", [None, "", "unknown", "webex,unknown"])
    def test_invalid_application_values(self, value):
        if value is None:
            assert normalize_application_names(value) == ()
        else:
            with pytest.raises(ValueError, match="application|Unknown"):
                normalize_application_names(value)

    def test_all_cannot_be_combined(self):
        with pytest.raises(ValueError, match="cannot be combined"):
            normalize_application_names("all,webex")

    def test_underscore_names_are_normalized(self):
        assert normalize_application_names("microsoft_teams") == ("microsoft-teams",)

    def test_payload_is_deterministic_and_in_range(self):
        profile = APPLICATION_PROFILES["webex"]
        flow = profile.flow_for(0)
        first = build_application_payload(profile, flow, client_index=2, packet_index=3)
        second = build_application_payload(profile, flow, client_index=2, packet_index=3)
        assert first == second
        assert flow.payload_min <= len(first) <= flow.payload_max
        assert b"fluxgen/webex/" in first
