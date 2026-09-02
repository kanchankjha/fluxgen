"""Declarative application-shaped traffic profiles.

The profiles describe useful L7 traffic shapes carried by raw TCP/UDP frames.
They intentionally use synthetic payloads: Fluxgen does not establish real
TCP/TLS sessions or authenticate to vendor applications.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple, Union


@dataclass(frozen=True)
class ApplicationFlow:
    """One transport-level flow shape belonging to an application profile."""

    name: str
    transport: str
    ports: Tuple[int, ...]
    payload_min: int
    payload_max: int
    tcp_flags: str = "PA"
    weight: int = 1

    def port_for(self, packet_index: int) -> int:
        return self.ports[packet_index % len(self.ports)]


@dataclass(frozen=True)
class ApplicationProfile:
    """Named application traffic profile composed of one or more flows."""

    name: str
    category: str
    flows: Tuple[ApplicationFlow, ...]

    def flow_for(self, packet_index: int) -> ApplicationFlow:
        weighted_flows = tuple(
            flow for flow in self.flows for _ in range(max(flow.weight, 1))
        )
        return weighted_flows[packet_index % len(weighted_flows)]


_APPLICATION_GROUPS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    (
        "collaboration",
        (
            "webex", "zoom", "microsoft-teams", "google-meet", "slack",
            "discord", "mattermost", "rocket-chat", "zulip", "jabber",
        ),
    ),
    (
        "productivity",
        (
            "outlook", "gmail", "exchange-online", "sharepoint", "onedrive",
            "google-drive", "dropbox", "box", "confluence", "notion",
        ),
    ),
    (
        "web-business",
        (
            "web-browsing", "https-saas", "rest-api", "graphql-api", "webhooks",
            "e-commerce", "salesforce", "servicenow", "jira", "sap",
        ),
    ),
    (
        "voice-media",
        (
            "voice", "video", "live-video", "video-on-demand", "music-streaming",
            "podcast", "webinar", "screen-sharing", "telemedicine", "online-classroom",
        ),
    ),
    (
        "network-services",
        (
            "dns", "dns-over-https", "dns-over-tls", "ntp", "dhcp", "ldap",
            "kerberos", "radius", "tacacs-plus", "snmp",
        ),
    ),
    (
        "iot-ot",
        (
            "iot", "mqtt", "mqtt-tls", "coap", "lwm2m", "modbus-tcp",
            "opc-ua", "bacnet-ip", "smart-meter", "sensor-telemetry",
        ),
    ),
    (
        "development-cloud",
        (
            "git-https", "git-ssh", "container-registry", "kubernetes-api",
            "cloud-object-storage", "ci-cd", "artifact-repository", "package-manager",
            "terraform-api", "serverless-invocation",
        ),
    ),
    (
        "data-database",
        (
            "data", "postgresql", "mysql", "mssql", "oracle-db", "redis",
            "mongodb", "elasticsearch", "kafka", "amqp",
        ),
    ),
    (
        "security-remote",
        (
            "ipsec-vpn", "ssl-vpn", "ssh", "rdp", "vnc", "winrm", "syslog",
            "siem-ingestion", "edr-telemetry", "vulnerability-scanner",
        ),
    ),
    (
        "consumer-edge",
        (
            "online-gaming", "game-voice-chat", "p2p-file-sharing", "software-update",
            "backup-sync", "smart-tv", "social-media", "ads-analytics",
            "video-surveillance", "digital-signage",
        ),
    ),
)


def _flow(
    name: str,
    transport: str,
    ports: Iterable[int],
    payload_min: int,
    payload_max: int,
    tcp_flags: str = "PA",
    weight: int = 1,
) -> ApplicationFlow:
    return ApplicationFlow(
        name=name,
        transport=transport,
        ports=tuple(ports),
        payload_min=payload_min,
        payload_max=payload_max,
        tcp_flags=tcp_flags,
        weight=weight,
    )


def _default_flows(category: str) -> Tuple[ApplicationFlow, ...]:
    if category == "collaboration":
        return (
            _flow("control", "tcp", (443,), 64, 900, weight=2),
            _flow("media", "udp", (3478, 5004), 160, 1200, weight=3),
        )
    if category == "productivity":
        return (_flow("transaction", "tcp", (443,), 80, 1400),)
    if category == "web-business":
        return (_flow("request", "tcp", (80, 443), 80, 1400),)
    if category == "voice-media":
        return (
            _flow("media", "udp", (5004, 3478), 160, 1200, weight=4),
            _flow("control", "tcp", (443,), 64, 600),
        )
    if category == "network-services":
        return (_flow("service", "udp", (123,), 32, 512),)
    if category == "iot-ot":
        return (_flow("telemetry", "tcp", (1883, 8883), 24, 512),)
    if category == "development-cloud":
        return (_flow("transaction", "tcp", (443,), 64, 1400),)
    if category == "data-database":
        return (_flow("data", "tcp", (443,), 128, 1400),)
    if category == "security-remote":
        return (_flow("session", "tcp", (443,), 64, 1200),)
    return (_flow("edge", "tcp", (443,), 64, 1200),)


_SPECIAL_FLOWS: Dict[str, Tuple[ApplicationFlow, ...]] = {
    "outlook": (_flow("mail", "tcp", (443,), 96, 1400), _flow("name-resolution", "udp", (53,), 32, 256)),
    "gmail": (_flow("mail", "tcp", (443,), 96, 1400), _flow("name-resolution", "udp", (53,), 32, 256)),
    "web-browsing": (_flow("http", "tcp", (80, 443), 96, 1400),),
    "https-saas": (_flow("https", "tcp", (443,), 96, 1400),),
    "rest-api": (_flow("api", "tcp", (443, 8443), 64, 900),),
    "graphql-api": (_flow("api", "tcp", (443,), 64, 1200),),
    "webhooks": (_flow("callback", "tcp", (443, 8443), 128, 900),),
    "voice": (_flow("signaling", "udp", (5060, 5061), 64, 300), _flow("rtp", "udp", (5004, 16384), 160, 320, weight=4)),
    "video": (_flow("signaling", "tcp", (443,), 64, 400), _flow("media", "udp", (5004, 3478), 400, 1400, weight=5)),
    "live-video": (_flow("media", "udp", (443, 5004), 400, 1400, weight=5), _flow("control", "tcp", (443,), 64, 500)),
    "video-on-demand": (_flow("media", "tcp", (443,), 400, 1400, weight=5),),
    "music-streaming": (_flow("media", "tcp", (443,), 256, 1400, weight=5),),
    "podcast": (_flow("media", "tcp", (443,), 256, 1400, weight=5),),
    "screen-sharing": (_flow("screen", "udp", (3478, 5004), 300, 1200, weight=4), _flow("control", "tcp", (443,), 64, 500)),
    "dns": (_flow("query", "udp", (53,), 32, 512), _flow("fallback", "tcp", (53,), 64, 900)),
    "dns-over-https": (_flow("query", "tcp", (443,), 64, 1200),),
    "dns-over-tls": (_flow("query", "tcp", (853,), 64, 1200),),
    "ntp": (_flow("time-query", "udp", (123,), 48, 192),),
    "dhcp": (_flow("lease", "udp", (67, 68), 240, 600),),
    "ldap": (_flow("directory", "tcp", (389, 636), 64, 900),),
    "kerberos": (_flow("authentication", "udp", (88,), 96, 900), _flow("fallback", "tcp", (88,), 96, 900)),
    "radius": (_flow("authentication", "udp", (1812, 1813), 64, 512),),
    "tacacs-plus": (_flow("authentication", "tcp", (49,), 64, 512),),
    "snmp": (_flow("poll", "udp", (161, 162), 64, 900),),
    "iot": (_flow("sensor", "udp", (1883, 5683), 24, 256),),
    "mqtt": (_flow("telemetry", "tcp", (1883,), 24, 512),),
    "mqtt-tls": (_flow("telemetry", "tcp", (8883,), 24, 512),),
    "coap": (_flow("telemetry", "udp", (5683,), 24, 256),),
    "lwm2m": (_flow("device-management", "udp", (5683, 5684), 32, 512),),
    "modbus-tcp": (_flow("industrial", "tcp", (502,), 12, 260),),
    "opc-ua": (_flow("industrial", "tcp", (4840,), 32, 900),),
    "bacnet-ip": (_flow("building-control", "udp", (47808,), 32, 512),),
    "smart-meter": (_flow("metering", "tcp", (443, 8883), 32, 512),),
    "sensor-telemetry": (_flow("telemetry", "udp", (5683, 1883), 24, 256),),
    "git-https": (_flow("repository", "tcp", (443,), 128, 1400),),
    "git-ssh": (_flow("repository", "tcp", (22,), 128, 1400),),
    "container-registry": (_flow("image-transfer", "tcp", (443, 5000), 256, 1400, weight=4),),
    "kubernetes-api": (_flow("control", "tcp", (6443, 443), 64, 1200),),
    "cloud-object-storage": (_flow("object-transfer", "tcp", (443,), 256, 1400, weight=4),),
    "ci-cd": (_flow("job-control", "tcp", (443,), 64, 900), _flow("artifact", "tcp", (443,), 256, 1400, weight=3)),
    "artifact-repository": (_flow("artifact", "tcp", (443, 8081), 256, 1400, weight=4),),
    "package-manager": (_flow("package", "tcp", (80, 443), 128, 1400, weight=4),),
    "terraform-api": (_flow("infrastructure", "tcp", (443,), 64, 900),),
    "serverless-invocation": (_flow("invocation", "tcp", (443,), 64, 900),),
    "data": (_flow("bulk-data", "tcp", (443, 8443), 256, 1400, weight=5),),
    "postgresql": (_flow("database", "tcp", (5432,), 64, 1200),),
    "mysql": (_flow("database", "tcp", (3306,), 64, 1200),),
    "mssql": (_flow("database", "tcp", (1433,), 64, 1200),),
    "oracle-db": (_flow("database", "tcp", (1521,), 64, 1200),),
    "redis": (_flow("cache", "tcp", (6379,), 32, 512),),
    "mongodb": (_flow("database", "tcp", (27017,), 64, 1200),),
    "elasticsearch": (_flow("search", "tcp", (9200, 443), 64, 1200),),
    "kafka": (_flow("stream", "tcp", (9092, 9093), 64, 1400, weight=3),),
    "amqp": (_flow("queue", "tcp", (5672, 5671), 64, 900),),
    "ipsec-vpn": (_flow("ike", "udp", (500, 4500), 64, 512),),
    "ssl-vpn": (_flow("tunnel", "tcp", (443, 8443), 128, 1400, weight=4),),
    "ssh": (_flow("terminal", "tcp", (22,), 16, 512),),
    "rdp": (_flow("desktop", "tcp", (3389,), 64, 1200), _flow("fast-path", "udp", (3389,), 64, 1200, weight=2)),
    "vnc": (_flow("desktop", "tcp", (5900,), 64, 1200),),
    "winrm": (_flow("management", "tcp", (5985, 5986), 64, 900),),
    "syslog": (_flow("logging", "udp", (514,), 64, 900),),
    "siem-ingestion": (_flow("logging", "tcp", (443, 6514), 128, 1200, weight=3),),
    "edr-telemetry": (_flow("telemetry", "tcp", (443,), 64, 900),),
    "vulnerability-scanner": (_flow("scan", "tcp", (443, 80), 64, 512),),
    "online-gaming": (_flow("game-state", "udp", (3074, 27015), 32, 900, weight=4), _flow("matchmaking", "tcp", (443,), 64, 512)),
    "game-voice-chat": (_flow("voice", "udp", (5004, 3478), 80, 320, weight=4),),
    "p2p-file-sharing": (_flow("peer-data", "tcp", (6881, 51413), 256, 1400, weight=5),),
    "software-update": (_flow("download", "tcp", (80, 443), 256, 1400, weight=5),),
    "backup-sync": (_flow("backup", "tcp", (443, 873), 256, 1400, weight=5),),
    "smart-tv": (_flow("media", "tcp", (443,), 256, 1400, weight=4),),
    "social-media": (_flow("feed", "tcp", (443,), 64, 1400),),
    "ads-analytics": (_flow("analytics", "tcp", (443,), 64, 900),),
    "video-surveillance": (_flow("camera", "udp", (554, 5004), 256, 1400, weight=5),),
    "digital-signage": (_flow("content", "tcp", (443, 8080), 256, 1400, weight=4),),
}


def _build_profiles() -> Dict[str, ApplicationProfile]:
    profiles: Dict[str, ApplicationProfile] = {}
    for category, names in _APPLICATION_GROUPS:
        for name in names:
            profiles[name] = ApplicationProfile(
                name=name,
                category=category,
                flows=_SPECIAL_FLOWS.get(name, _default_flows(category)),
            )
    return profiles


APPLICATION_PROFILES: Dict[str, ApplicationProfile] = _build_profiles()
APPLICATION_NAMES: Tuple[str, ...] = tuple(
    name for _, names in _APPLICATION_GROUPS for name in names
)


def normalize_application_names(
    value: Optional[Union[str, Iterable[str]]],
) -> Tuple[str, ...]:
    """Normalize CLI/config values and validate profile names."""
    if value is None:
        return ()
    if isinstance(value, str):
        values = (value,)
    else:
        try:
            values = tuple(value)
        except TypeError as exc:
            raise ValueError("application must contain profile names") from exc
    names: List[str] = []
    for raw_value in values:
        if not isinstance(raw_value, str):
            raise ValueError("application must contain profile names")
        names.extend(
            part.strip().lower().replace("_", "-")
            for part in raw_value.split(",")
            if part.strip()
        )
    if not names:
        raise ValueError("application must contain at least one profile name")
    if "all" in names:
        if len(names) != 1:
            raise ValueError("application=all cannot be combined with other profiles")
        return ("all",)
    unknown = [name for name in names if name not in APPLICATION_PROFILES]
    if unknown:
        raise ValueError(f"Unknown application profile: {unknown[0]}")
    return tuple(names)


def select_application_profile(
    names: Tuple[str, ...],
    client_index: int,
    packet_index: int,
) -> Optional[ApplicationProfile]:
    """Select a deterministic profile for one simulated client send."""
    if not names:
        return None
    available = APPLICATION_NAMES if names == ("all",) else names
    selected_name = available[(client_index + packet_index) % len(available)]
    return APPLICATION_PROFILES[selected_name]


def build_application_payload(
    profile: ApplicationProfile,
    flow: ApplicationFlow,
    client_index: int,
    packet_index: int,
) -> bytes:
    """Build deterministic synthetic bytes matching a profile's size range."""
    seed = f"{profile.name}:{flow.name}:{client_index}:{packet_index}".encode("utf-8")
    digest = hashlib.blake2b(seed, digest_size=32).digest()
    size = flow.payload_min
    if flow.payload_max > flow.payload_min:
        size += int.from_bytes(digest[:4], "big") % (flow.payload_max - flow.payload_min + 1)
    marker = f"fluxgen/{profile.name}/{flow.name}/".encode("utf-8")
    output = bytearray()
    while len(output) < size:
        output.extend(marker)
        output.extend(digest)
    return bytes(output[:size])


def identify_application_payload(payload: bytes) -> Optional[Tuple[ApplicationProfile, ApplicationFlow]]:
    """Identify a Fluxgen profile marker embedded in synthetic payload bytes."""
    if not payload:
        return None
    try:
        marker = payload.split(b"fluxgen/", 1)[1].split(b"/", 2)
        profile_name = marker[0].decode("ascii")
        flow_name = marker[1].decode("ascii")
    except (IndexError, UnicodeDecodeError):
        return None
    profile = APPLICATION_PROFILES.get(profile_name)
    if profile is None:
        return None
    for flow in profile.flows:
        if flow.name == flow_name:
            return profile, flow
    return None


def select_responder_flow(
    names: Tuple[str, ...],
    transport: str,
    port: int,
    payload: bytes = b"",
) -> Optional[Tuple[ApplicationProfile, ApplicationFlow]]:
    """Select a responder flow using a marker, configured names, or port."""
    identified = identify_application_payload(payload)
    allowed = set(APPLICATION_NAMES if names == ("all",) else names)
    if identified and (not names or identified[0].name in allowed):
        return identified
    candidates = APPLICATION_NAMES if names in ((), ("all",)) else names
    for name in candidates:
        profile = APPLICATION_PROFILES[name]
        for flow in profile.flows:
            if flow.transport == transport and port in flow.ports:
                return profile, flow
    return None


def build_application_response_payload(
    profile: ApplicationProfile,
    flow: ApplicationFlow,
    request_index: int = 0,
) -> bytes:
    """Build deterministic synthetic response bytes for an application flow."""
    seed = f"response:{profile.name}:{flow.name}:{request_index}".encode("utf-8")
    digest = hashlib.blake2b(seed, digest_size=32).digest()
    size = flow.payload_min
    if flow.payload_max > flow.payload_min:
        size += int.from_bytes(digest[:4], "big") % (flow.payload_max - flow.payload_min + 1)
    marker = f"fluxgen-response/{profile.name}/{flow.name}/".encode("utf-8")
    output = bytearray()
    while len(output) < size:
        output.extend(marker)
        output.extend(digest)
    return bytes(output[:size])


def application_profile_count() -> int:
    """Return the number of built-in application profiles."""
    return len(APPLICATION_PROFILES)
