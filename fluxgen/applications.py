"""Declarative application traffic profiles and protocol-native payloads.

The profiles are deliberately representative rather than authenticated vendor
clients.  They use valid, classifier-visible protocol framing and public
application metadata (for example HTTP Host and TLS SNI) so a DUT can inspect
the traffic as an application flow.
"""

from __future__ import annotations

import hashlib
import ipaddress
import struct
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple, Union

try:
    from scapy.contrib.coap import CoAP  # type: ignore
except ImportError:  # pragma: no cover - provided by supported Scapy versions
    CoAP = None  # type: ignore
from scapy.all import Raw  # type: ignore

try:
    from scapy.layers.kerberos import KRB_AS_REP, KRB_AS_REQ, KRB_KDC_REQ_BODY  # type: ignore
except ImportError:  # pragma: no cover - provided by supported Scapy versions
    KRB_AS_REP = KRB_AS_REQ = KRB_KDC_REQ_BODY = None  # type: ignore


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
    signature: str = "raw"

    def port_for(self, packet_index: int) -> int:
        return self.ports[packet_index % len(self.ports)]


@dataclass(frozen=True)
class ApplicationProfile:
    """Named application traffic profile composed of one or more flows."""

    name: str
    category: str
    flows: Tuple[ApplicationFlow, ...]
    hostname: str = ""

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
    signature: str = "raw",
) -> ApplicationFlow:
    return ApplicationFlow(
        name=name,
        transport=transport,
        ports=tuple(ports),
        payload_min=payload_min,
        payload_max=payload_max,
        tcp_flags=tcp_flags,
        weight=weight,
        signature=signature,
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
    "voice": (_flow("signaling", "udp", (5060, 5061), 64, 400), _flow("rtp", "udp", (5004, 16384), 160, 320, weight=4)),
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
    "iot": (_flow("telemetry", "tcp", (1883,), 24, 512), _flow("sensor", "udp", (5683,), 24, 256)),
    "mqtt": (_flow("telemetry", "tcp", (1883,), 24, 512),),
    "mqtt-tls": (_flow("telemetry", "tcp", (8883,), 24, 512),),
    "coap": (_flow("telemetry", "udp", (5683,), 24, 256),),
    "lwm2m": (_flow("device-management", "udp", (5683, 5684), 32, 512),),
    "modbus-tcp": (_flow("industrial", "tcp", (502,), 12, 260),),
    "opc-ua": (_flow("industrial", "tcp", (4840,), 32, 900),),
    "bacnet-ip": (_flow("building-control", "udp", (47808,), 32, 512),),
    "smart-meter": (_flow("metering", "tcp", (443, 8883), 32, 512),),
    "sensor-telemetry": (_flow("telemetry", "udp", (5683,), 24, 256), _flow("broker", "tcp", (1883,), 24, 512)),
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
    "winrm": (_flow("management", "tcp", (5985,), 64, 900), _flow("secure-management", "tcp", (5986,), 64, 900)),
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


_KNOWN_HOSTNAMES: Dict[str, str] = {
    "webex": "webex.com",
    "zoom": "zoom.us",
    "microsoft-teams": "teams.microsoft.com",
    "google-meet": "meet.google.com",
    "slack": "slack.com",
    "discord": "discord.com",
    "mattermost": "mattermost.com",
    "rocket-chat": "rocket.chat",
    "zulip": "zulip.com",
    "jabber": "jabber.org",
    "outlook": "outlook.office.com",
    "gmail": "mail.google.com",
    "exchange-online": "outlook.office365.com",
    "sharepoint": "sharepoint.com",
    "onedrive": "onedrive.live.com",
    "google-drive": "drive.google.com",
    "dropbox": "dropbox.com",
    "box": "box.com",
    "confluence": "atlassian.com",
    "notion": "notion.so",
    "salesforce": "salesforce.com",
    "servicenow": "servicenow.com",
    "jira": "atlassian.com",
    "sap": "sap.com",
    "git-https": "github.com",
    "container-registry": "registry-1.docker.io",
    "cloud-object-storage": "s3.amazonaws.com",
    "software-update": "download.microsoft.com",
    "social-media": "facebook.com",
    "smart-tv": "roku.com",
    "video-surveillance": "onvif.org",
}


def _profile_hostname(name: str) -> str:
    """Return a stable public-looking hostname for visible L7 metadata."""
    return _KNOWN_HOSTNAMES.get(name, f"{name}.fluxgen.invalid")


def _signature_for(name: str, flow: ApplicationFlow) -> str:
    """Choose a protocol serializer for an existing transport flow.

    The catalog intentionally remains 100 names, but profiles now share a
    finite set of real protocol families.  Application-specific identity is
    carried in fields visible to a classifier, such as SNI, Host, URI, or a
    protocol client identifier.
    """
    if 53 in flow.ports:
        return "dns"
    if flow.transport == "udp":
        if name == "rdp" or 3389 in flow.ports:
            return "rdp"
        if 123 in flow.ports:
            return "ntp"
        if 67 in flow.ports or 68 in flow.ports:
            return "dhcp"
        if 5060 in flow.ports or flow.name == "signaling":
            return "sip"
        if 5004 in flow.ports or 3478 in flow.ports or flow.name in {"rtp", "media", "screen", "voice"}:
            return "rtp"
        if 5683 in flow.ports:
            return "coap"
        if 161 in flow.ports or 162 in flow.ports:
            return "snmp"
        if 514 in flow.ports:
            return "syslog"
        if 47808 in flow.ports:
            return "bacnet"
        if name == "radius" or 1812 in flow.ports or 1813 in flow.ports:
            return "radius"
        if name == "ipsec-vpn" or 500 in flow.ports or 4500 in flow.ports:
            return "ike"
        if name == "kerberos" or 88 in flow.ports:
            return "kerberos"
        if name == "online-gaming":
            return "game"
        return "udp"

    if name == "kerberos" or 88 in flow.ports:
        return "kerberos"
    if name == "tacacs-plus" or 49 in flow.ports:
        return "tacacs"
    if name == "rdp" or 3389 in flow.ports:
        return "rdp"
    if name == "vnc" or 5900 in flow.ports:
        return "vnc"
    if name == "winrm":
        return "http" if 5985 in flow.ports else "tls"
    if name == "p2p-file-sharing" or 6881 in flow.ports or 51413 in flow.ports:
        return "bittorrent"
    if 22 in flow.ports or name == "ssh":
        return "ssh"
    if name == "postgresql" or 5432 in flow.ports:
        return "postgresql"
    if name == "mysql" or 3306 in flow.ports:
        return "mysql"
    if name == "mssql" or 1433 in flow.ports:
        return "mssql"
    if name == "oracle-db" or 1521 in flow.ports:
        return "oracle"
    if name == "redis" or 6379 in flow.ports:
        return "redis"
    if name == "mongodb" or 27017 in flow.ports:
        return "mongodb"
    if name == "kafka" or 9092 in flow.ports or 9093 in flow.ports:
        return "kafka"
    if name == "amqp" or 5672 in flow.ports or 5671 in flow.ports:
        return "amqp"
    if name == "modbus-tcp" or 502 in flow.ports:
        return "modbus"
    if name == "opc-ua" or 4840 in flow.ports:
        return "opcua"
    if name == "ldap" or 389 in flow.ports:
        return "ldap"
    if name in {"web-browsing", "package-manager", "webhooks"} or 80 in flow.ports:
        return "http"
    if 1883 in flow.ports and flow.transport == "tcp":
        return "mqtt"
    if name == "mqtt-tls":
        return "tls"
    if name in {"dns-over-https", "dns-over-tls"}:
        return "tls"
    return "tls" if 443 in flow.ports or 8443 in flow.ports or 8081 in flow.ports else "tcp"


def _decorate_profile(profile: ApplicationProfile) -> ApplicationProfile:
    flows = tuple(
        ApplicationFlow(
            name=flow.name,
            transport=flow.transport,
            ports=flow.ports,
            payload_min=flow.payload_min,
            payload_max=flow.payload_max,
            tcp_flags=flow.tcp_flags,
            weight=flow.weight,
            signature=_signature_for(profile.name, flow),
        )
        for flow in profile.flows
    )
    return ApplicationProfile(
        name=profile.name,
        category=profile.category,
        flows=flows,
        hostname=_profile_hostname(profile.name),
    )


def _build_profiles() -> Dict[str, ApplicationProfile]:
    profiles: Dict[str, ApplicationProfile] = {}
    for category, names in _APPLICATION_GROUPS:
        for name in names:
            profiles[name] = _decorate_profile(ApplicationProfile(
                name=name,
                category=category,
                flows=_SPECIAL_FLOWS.get(name, _default_flows(category)),
            ))
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


def _digest(seed: bytes, size: int = 32) -> bytes:
    return hashlib.blake2b(seed, digest_size=size).digest()


def _encoded_name(profile: ApplicationProfile) -> bytes:
    return profile.name.replace("-", "_").encode("ascii")


def _dns_name(name: str) -> bytes:
    return b"".join(bytes((len(label),)) + label.encode("ascii") for label in name.split(".")) + b"\x00"


def _tls_extension(extension_type: int, value: bytes) -> bytes:
    return struct.pack("!HH", extension_type, len(value)) + value


def _tls_record(content_type: int, payload: bytes) -> bytes:
    return struct.pack("!BHH", content_type, 0x0301, len(payload)) + payload


def _tls_client_hello(profile: ApplicationProfile, seed: bytes) -> bytes:
    hostname = profile.hostname.encode("idna")
    sni = struct.pack("!H", len(hostname) + 3) + b"\x00" + struct.pack("!H", len(hostname)) + hostname
    alpn_names = b"\x02h2\x08http/1.1"
    alpn = struct.pack("!H", len(alpn_names)) + alpn_names
    supported_versions = b"\x02\x03\x04"
    extensions = (
        _tls_extension(0, sni)
        + _tls_extension(16, alpn)
        + _tls_extension(43, supported_versions)
        + _tls_extension(10, b"\x00\x04\x00\x1d\x00\x17")
    )
    body = (
        b"\x03\x03" + _digest(seed, 32) + b"\x00"
        + struct.pack("!H", 4) + b"\x13\x01\x13\x02"
        + b"\x01\x00" + struct.pack("!H", len(extensions)) + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return _tls_record(22, handshake)


def _tls_server_hello(profile: ApplicationProfile, seed: bytes) -> bytes:
    extensions = _tls_extension(43, b"\x03\x04")
    body = b"\x03\x03" + _digest(seed, 32) + b"\x00\x13\x01\x00"
    body += struct.pack("!H", len(extensions)) + extensions
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return _tls_record(22, handshake)


def _http_request(profile: ApplicationProfile, client_index: int, packet_index: int) -> bytes:
    path = f"/{profile.name}/api/v1/health?client={client_index}&request={packet_index}"
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {profile.hostname}\r\n"
        "User-Agent: Fluxgen/2.0 (application traffic simulator)\r\n"
        "Accept: application/json\r\n"
        "Accept-Encoding: gzip\r\n"
        "Connection: keep-alive\r\n\r\n"
    ).encode("ascii")


def _dns_query(profile: ApplicationProfile, seed: bytes) -> bytes:
    query_id = struct.unpack("!H", _digest(seed, 2))[0]
    return struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 1) + _dns_name(profile.hostname) + struct.pack("!HH", 1, 1) + b"\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x00"


def _dns_response(profile: ApplicationProfile, seed: bytes, request: bytes = b"") -> bytes:
    query_id = request[:2] if len(request) >= 2 else _digest(seed, 2)
    question = _dns_name(profile.hostname) + struct.pack("!HH", 1, 1)
    return (
        query_id + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
        + question + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4)
        + ipaddress.IPv4Address("192.0.2.1").packed
    )


def _dns_query_name(payload: bytes) -> Optional[str]:
    """Extract the first DNS question name without relying on Scapy layers."""
    if len(payload) < 13:
        return None
    offset = 12
    labels: List[str] = []
    while offset < len(payload):
        length = payload[offset]
        offset += 1
        if length == 0:
            return ".".join(labels)
        if length > 63 or offset + length > len(payload):
            return None
        try:
            labels.append(payload[offset:offset + length].decode("ascii"))
        except UnicodeDecodeError:
            return None
        offset += length
    return None


def _coap_path(payload: bytes) -> Optional[str]:
    """Extract the first URI-Path option from a compact CoAP request."""
    if len(payload) < 5:
        return None
    token_length = payload[0] & 0x0F
    offset = 4 + token_length
    if offset >= len(payload):
        return None
    option = payload[offset]
    offset += 1
    length = option & 0x0F
    if length == 13:
        if offset >= len(payload):
            return None
        length = payload[offset] + 13
        offset += 1
    elif length == 14:
        if offset + 1 >= len(payload):
            return None
        length = int.from_bytes(payload[offset:offset + 2], "big") + 269
        offset += 2
    if (option >> 4) != 11 or offset + length > len(payload):
        return None
    try:
        return payload[offset:offset + length].decode("ascii")
    except UnicodeDecodeError:
        return None


def _mqtt_length(value: int) -> bytes:
    encoded = bytearray()
    while True:
        digit = value % 128
        value //= 128
        if value:
            digit |= 0x80
        encoded.append(digit)
        if not value:
            return bytes(encoded)


def _mqtt_connect(profile: ApplicationProfile, client_index: int) -> bytes:
    client_id = f"fluxgen-{profile.name}-{client_index}".encode("utf-8")
    variable = b"\x00\x04MQTT\x04\x02\x00<" + struct.pack("!H", len(client_id)) + client_id
    return b"\x10" + _mqtt_length(len(variable)) + variable


def _sip_request(profile: ApplicationProfile, client_index: int) -> bytes:
    host = profile.hostname
    return (
        f"INVITE sip:service@{host} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP client.fluxgen.invalid:5060;branch=z9hG4bK-{client_index}\r\n"
        f"From: <sip:client@fluxgen.invalid>;tag={client_index}\r\n"
        f"To: <sip:service@{host}>\r\n"
        "Call-ID: fluxgen-call-1@fluxgen.invalid\r\n"
        "CSeq: 1 INVITE\r\n"
        "Contact: <sip:client@fluxgen.invalid>\r\n"
        "Content-Length: 0\r\n\r\n"
    ).encode("ascii")


def _sip_response(profile: ApplicationProfile) -> bytes:
    return (
        "SIP/2.0 200 OK\r\n"
        "Via: SIP/2.0/UDP client.fluxgen.invalid:5060;branch=z9hG4bK-0\r\n"
        f"From: <sip:client@fluxgen.invalid>;tag=0\r\nTo: <sip:service@{profile.hostname}>;tag=server\r\n"
        "Call-ID: fluxgen-call-1@fluxgen.invalid\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
    ).encode("ascii")


def _rtp_packet(profile: ApplicationProfile, packet_index: int, seed: bytes, response: bool = False) -> bytes:
    payload_type = 0 if profile.name == "voice" else 96
    sequence = packet_index & 0xFFFF
    timestamp = (packet_index * 160) & 0xFFFFFFFF
    ssrc = struct.unpack("!I", _digest(profile.name.encode("ascii"), 4))[0]
    header = struct.pack("!BBHII", 0x80, payload_type, sequence, timestamp, ssrc)
    media = (_encoded_name(profile) + b"/" + _digest(seed, 32))
    return header + media + (b"-response" if response else b"")


def _ntp_packet(seed: bytes, response: bool = False) -> bytes:
    packet = bytearray(48)
    packet[0] = 0x24 if response else 0x23  # version 4, server/client mode
    packet[1] = 2 if response else 0
    packet[40:48] = _digest(seed, 8)
    return bytes(packet)


def _ike_init(profile: ApplicationProfile, seed: bytes, response: bool = False) -> bytes:
    """Build an IKEv2 IKE_SA_INIT-shaped exchange."""
    initiator_spi = _digest(profile.name.encode("ascii"), 8)
    responder_spi = _digest(seed + b"responder", 8) if response else b"\x00" * 8
    next_payload = 34 if not response else 0
    flags = 0x20 if response else 0x08
    exchange = 34
    body = b""  # A minimal header is sufficient for IKE signature detection.
    length = 28 + len(body)
    return initiator_spi + responder_spi + bytes((next_payload, 0x20, exchange, flags)) + struct.pack("!II", 0, length) + body


def _kerberos_request(profile: ApplicationProfile, seed: bytes, response: bool = False) -> bytes:
    """Build a DER-encoded Kerberos AS-REQ or minimal AS-REP."""
    if KRB_AS_REQ is not None and KRB_AS_REP is not None:
        if response:
            return bytes(KRB_AS_REP(crealm=profile.hostname.upper()))
        nonce = struct.unpack("!I", _digest(seed, 4))[0]
        request = KRB_AS_REQ(
            reqBody=KRB_KDC_REQ_BODY(
                realm=profile.hostname.upper(),
                nonce=nonce,
                etype=[23],
            )
        )
        return bytes(request)
    # Conservative fallback for environments with an older Scapy build.
    realm = _ber(0x1b, profile.hostname.upper().encode("ascii"))
    principal = _ber(0x30, _ber(0x02, b"\x01") + _ber(0x30, realm + _ber(0x1b, _encoded_name(profile))))
    request_body = _ber(0x30, _ber(0xa1, _ber(0x02, b"\x01")) + _ber(0xa3, principal))
    return _ber(0x6b if response else 0x6a, _ber(0xa0, _ber(0x02, b"\x05")) + _ber(0xa2, request_body))


def _tacacs_packet(profile: ApplicationProfile, seed: bytes, response: bool = False) -> bytes:
    version = 0xc0
    packet_type = 1
    flags = 0x01  # Explicitly unencrypted for deterministic test inspection.
    session_id = struct.unpack("!I", _digest(profile.name.encode("ascii"), 4))[0]
    if response:
        body = struct.pack("!BBHH", 1, 0, len(b"ok"), 0) + b"ok"
        sequence = 2
    else:
        user = _encoded_name(profile)
        port = b"tty0"
        address = b"fluxgen"
        body = struct.pack("!BBBBHHHH", 1, 1, 1, 1, len(user), len(port), len(address), 0)
        body += user + port + address
        sequence = 1
    return bytes((version, packet_type, sequence, flags)) + struct.pack("!II", session_id, len(body)) + body


def _rdp_request(profile: ApplicationProfile, response: bool = False) -> bytes:
    # X.224 connection request/confirm with an RDP Negotiation Request.
    cookie = b"Cookie: mstshash=" + _encoded_name(profile) + b"\r\n"
    tpdu = b"\x06\xe0\x00\x00\x00\x00\x00"
    return b"\x03\x00" + struct.pack("!H", 4 + len(tpdu) + len(cookie)) + tpdu + cookie


def _vnc_banner(profile: ApplicationProfile, response: bool = False) -> bytes:
    version = "RFB 003.008\n" if response else f"RFB 003.008 Fluxgen-{profile.name}\n"
    return version.encode("ascii")


def _game_packet(profile: ApplicationProfile, packet_index: int, seed: bytes, response: bool = False) -> bytes:
    # A valid STUN Binding transaction is a common classifier-visible
    # building block for game and real-time media connectivity.
    message_type = 0x0101 if response else 0x0001
    transaction_id = _digest(profile.name.encode("ascii") + struct.pack("!H", packet_index), 12)
    software = b"Fluxgen-" + _encoded_name(profile)
    attribute = struct.pack("!HH", 0x8022, len(software)) + software
    if len(software) % 4:
        attribute += b"\x00" * (4 - (len(software) % 4))
    return struct.pack("!HHI", message_type, len(attribute), 0x2112A442) + transaction_id + attribute


def _bittorrent_handshake(profile: ApplicationProfile, seed: bytes, response: bool = False) -> bytes:
    info_hash = _digest(profile.name.encode("ascii"), 20)
    peer_id = (b"-FG2000-" + _digest(seed, 12))[:20]
    return b"\x13BitTorrent protocol" + b"\x00" * 8 + info_hash + peer_id


def _dhcp_discover(profile: ApplicationProfile, seed: bytes) -> bytes:
    xid = struct.unpack("!I", _digest(seed, 4))[0]
    chaddr = b"\x02\x00\x00" + _digest(profile.name.encode("ascii"), 3) + b"\x00" * 10
    bootp = struct.pack("!BBBBIHHIIII16s64s128s", 1, 1, 6, 0, xid, 0, 0x8000, 0, 0, 0, 0, chaddr, b"", b"")
    options = b"\x35\x01\x01\x0c" + bytes((len(profile.name),)) + profile.name.encode("ascii") + b"\xff"
    return bootp + b"\x63\x82\x53\x63" + options


def _dhcp_offer(profile: ApplicationProfile, seed: bytes) -> bytes:
    xid = struct.unpack("!I", _digest(seed, 4))[0]
    chaddr = b"\x02\x00\x00" + _digest(profile.name.encode("ascii"), 3) + b"\x00" * 10
    bootp = struct.pack("!BBBBIHHIIII16s64s128s", 2, 1, 6, 0, xid, 0, 0x8000, 0, 0, 0, 0, chaddr, b"", b"")
    return bootp + b"\x63\x82\x53\x63\x35\x01\x02\xff"


def _coap_request(profile: ApplicationProfile, packet_index: int) -> bytes:
    if CoAP is not None:
        return bytes(
            CoAP(
                type=0,
                code=1,
                msg_id=packet_index & 0xFFFF,
                token=bytes((packet_index & 0xFF,)),
                options=[("Uri-Path", profile.name)],
                paymark=b"\xff",
            ) / Raw(load=b"application=" + _encoded_name(profile))
        )
    token = bytes((packet_index & 0xFF,))
    path = profile.name.encode("ascii")
    if len(path) < 13:
        option = bytes((11 << 4 | len(path),)) + path
    else:
        option = bytes((11 << 4 | 13, len(path) - 13)) + path
    return bytes((0x41, 0x01, (packet_index >> 8) & 0xFF, packet_index & 0xFF)) + token + option


def _coap_response(profile: ApplicationProfile, packet_index: int) -> bytes:
    if CoAP is not None:
        return bytes(
            CoAP(
                type=2,
                code=69,
                msg_id=packet_index & 0xFFFF,
                token=bytes((packet_index & 0xFF,)),
                paymark=b"\xff",
            ) / Raw(load=b"application=" + _encoded_name(profile))
        )
    return bytes((0x61, 0x45, (packet_index >> 8) & 0xFF, packet_index & 0xFF, packet_index & 0xFF)) + b"Fluxgen " + _encoded_name(profile)


def _modbus_request(packet_index: int) -> bytes:
    transaction = packet_index & 0xFFFF
    return struct.pack("!HHHBBHH", transaction, 0, 6, 1, 3, 0, 2)


def _modbus_response(packet_index: int) -> bytes:
    transaction = packet_index & 0xFFFF
    return struct.pack("!HHHBBBHH", transaction, 0, 7, 1, 3, 4, 1, 2)


def _opcua_hello(profile: ApplicationProfile) -> bytes:
    endpoint = f"opc.tcp://{profile.hostname}:4840".encode("ascii") + b"\x00"
    length = 8 + 20 + len(endpoint)
    return b"HEL" + struct.pack("!I", length) + struct.pack("!IIIII", 0, 65535, 65535, 0, 0) + endpoint


def _opcua_ack(profile: ApplicationProfile) -> bytes:
    return b"ACK" + struct.pack("!I", 32) + struct.pack("!IIIIII", 0, 0, 0, 0, 0, 0)


def _bacnet_who_is(profile: ApplicationProfile) -> bytes:
    # BVLL + NPDU + Who-Is APDU, with the profile name as an application tag.
    body = b"\x01\x00\x00\x00\x10\x08\x00\x00" + _encoded_name(profile)
    return b"\x81\x0a" + struct.pack("!H", len(body) + 4) + body


def _bacnet_i_am(profile: ApplicationProfile) -> bytes:
    body = b"\x01\x00\x00\x00\x10\x00\x00\x00" + _encoded_name(profile)
    return b"\x81\x0a" + struct.pack("!H", len(body) + 4) + body


def _ber_length(length: int) -> bytes:
    if length < 128:
        return bytes((length,))
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes((0x80 | len(raw),)) + raw


def _ber(tag: int, value: bytes) -> bytes:
    return bytes((tag,)) + _ber_length(len(value)) + value


def _ldap_bind(profile: ApplicationProfile) -> bytes:
    name = _ber(0x04, f"cn={profile.name}".encode("ascii"))
    simple = _ber(0x80, b"fluxgen")
    bind = _ber(0x60, _ber(0x02, b"\x03") + name + simple)
    return _ber(0x30, _ber(0x02, b"\x01") + bind)


def _ldap_bind_response() -> bytes:
    result = _ber(0x61, _ber(0x0a, b"\x00") + _ber(0x04, b"") + _ber(0x04, b""))
    return _ber(0x30, _ber(0x02, b"\x01") + result)


def _radius_access_request(profile: ApplicationProfile, seed: bytes) -> bytes:
    request_id = _digest(seed, 1)
    authenticator = _digest(seed + b"auth", 16)
    username = _ber(0x00, profile.name.encode("ascii"))
    attributes = b"\x01" + bytes((len(username) + 2,)) + username
    length = 20 + len(attributes)
    return b"\x01" + request_id + struct.pack("!H", length) + authenticator + attributes


def _radius_access_accept(seed: bytes) -> bytes:
    return b"\x02" + _digest(seed, 1) + struct.pack("!H", 20) + _digest(seed + b"auth", 16)


def _snmp_get(profile: ApplicationProfile) -> bytes:
    # SNMPv1 GetRequest for sysDescr.0, with the profile in the community.
    oid = b"\x2b\x06\x01\x02\x01\x01\x01\x00"
    varbind = _ber(0x30, _ber(0x06, oid) + _ber(0x05, b""))
    pdu = _ber(0xa0, _ber(0x02, b"\x01") + _ber(0x02, b"\x00") + _ber(0x02, b"\x00") + _ber(0x30, varbind))
    message = _ber(0x30, _ber(0x02, b"\x00") + _ber(0x04, _encoded_name(profile)) + pdu)
    return message


def _snmp_response(profile: ApplicationProfile) -> bytes:
    return _snmp_get(profile).replace(b"\xa0", b"\xa2", 1)


def _syslog_message(profile: ApplicationProfile, packet_index: int, response: bool = False) -> bytes:
    app = f"fluxgen-{profile.name}"
    message = "response" if response else "telemetry"
    return f"<134>1 2026-01-01T00:00:00Z fluxgen {app} - - [{profile.name}] {message} packet={packet_index}\n".encode("ascii")


def _database_request(profile: ApplicationProfile, signature: str, packet_index: int) -> bytes:
    if signature == "postgresql":
        params = b"user\x00fluxgen\x00application_name\x00" + _encoded_name(profile) + b"\x00\x00"
        return struct.pack("!II", len(params) + 8, 196608) + params
    if signature == "mysql":
        query = f"/* {profile.name} */ SELECT 1".encode("ascii")
        return bytes((len(query) + 1, 0, 0, 0, 3)) + query
    if signature == "redis":
        return b"*2\r\n$4\r\nPING\r\n$" + str(len(profile.name)).encode() + b"\r\n" + _encoded_name(profile) + b"\r\n"
    if signature == "amqp":
        return b"AMQP\x00\x00\x09\x01"
    if signature == "kafka":
        client_id = _encoded_name(profile)
        body = struct.pack("!hhih", 18, 0, packet_index & 0xFFFFFFFF, len(client_id)) + client_id
        return struct.pack("!I", len(body)) + body
    return f"{signature.upper()} / {profile.name} / request={packet_index}\r\n".encode("ascii")


def _database_response(profile: ApplicationProfile, signature: str, packet_index: int) -> bytes:
    if signature == "redis":
        return b"+PONG\r\n"
    if signature == "amqp":
        return b"AMQP\x00\x00\x09\x01"
    if signature == "postgresql":
        return b"\x45\x00\x00\x00\x09\x00\x00\x00\x00\x5a\x00\x00\x00\x05I"
    if signature == "mysql":
        return b"\x01\x00\x00\x01\x01"
    return f"{signature.upper()} / {profile.name} / response={packet_index}\r\n".encode("ascii")


def _raw_application_request(profile: ApplicationProfile, flow: ApplicationFlow, seed: bytes) -> bytes:
    return f"APP/1.0 {profile.name} flow={flow.name}\r\n\r\n".encode("ascii") + _digest(seed, 16)


def _raw_application_response(profile: ApplicationProfile, flow: ApplicationFlow, seed: bytes) -> bytes:
    return f"APP/1.0 200 {profile.name} flow={flow.name}\r\n\r\n".encode("ascii") + _digest(seed, 16)


def _fit_payload(payload: bytes, flow: ApplicationFlow, seed: bytes) -> bytes:
    """Keep legacy size guarantees without replacing protocol framing.

    Padding is application data after the protocol header.  RTP uses it as
    media bytes, while TLS uses complete records; other protocols retain the
    valid prefix and receive deterministic trailing data for traffic-shape
    compatibility.
    """
    if len(payload) >= flow.payload_min:
        return payload
    needed = flow.payload_min - len(payload)
    if flow.signature == "tls":
        records = bytearray(payload)
        while len(records) < flow.payload_min:
            records.extend(_tls_record(20, b"\x01"))
        return bytes(records)
    filler = _digest(seed, 32)
    return payload + (filler * ((needed // len(filler)) + 1))[:needed]


def build_application_payload(
    profile: ApplicationProfile,
    flow: ApplicationFlow,
    client_index: int,
    packet_index: int,
) -> bytes:
    """Build a deterministic, protocol-native application request."""
    seed = f"{profile.name}:{flow.name}:{client_index}:{packet_index}".encode("utf-8")
    if flow.signature == "http":
        payload = _http_request(profile, client_index, packet_index)
    elif flow.signature == "tls":
        payload = _tls_client_hello(profile, seed)
    elif flow.signature == "dns":
        payload = _dns_query(profile, seed)
    elif flow.signature == "mqtt":
        payload = _mqtt_connect(profile, client_index)
    elif flow.signature == "sip":
        payload = _sip_request(profile, client_index)
    elif flow.signature == "rtp":
        payload = _rtp_packet(profile, packet_index, seed)
    elif flow.signature == "ssh":
        payload = f"SSH-2.0-Fluxgen_{profile.name}\r\n".encode("ascii")
    elif flow.signature == "ntp":
        payload = _ntp_packet(seed)
    elif flow.signature == "ike":
        payload = _ike_init(profile, seed)
    elif flow.signature == "kerberos":
        payload = _kerberos_request(profile, seed)
    elif flow.signature == "tacacs":
        payload = _tacacs_packet(profile, seed)
    elif flow.signature == "rdp":
        payload = _rdp_request(profile)
    elif flow.signature == "vnc":
        payload = _vnc_banner(profile)
    elif flow.signature == "game":
        payload = _game_packet(profile, packet_index, seed)
    elif flow.signature == "bittorrent":
        payload = _bittorrent_handshake(profile, seed)
    elif flow.signature == "dhcp":
        payload = _dhcp_discover(profile, seed)
    elif flow.signature == "coap":
        payload = _coap_request(profile, packet_index)
    elif flow.signature == "modbus":
        payload = _modbus_request(packet_index)
    elif flow.signature == "opcua":
        payload = _opcua_hello(profile)
    elif flow.signature == "bacnet":
        payload = _bacnet_who_is(profile)
    elif flow.signature == "ldap":
        payload = _ldap_bind(profile)
    elif flow.signature == "radius":
        payload = _radius_access_request(profile, seed)
    elif flow.signature == "snmp":
        payload = _snmp_get(profile)
    elif flow.signature == "syslog":
        payload = _syslog_message(profile, packet_index)
    elif flow.signature in {"postgresql", "mysql", "mssql", "oracle", "redis", "mongodb", "kafka", "amqp"}:
        payload = _database_request(profile, flow.signature, packet_index)
    else:
        payload = _raw_application_request(profile, flow, seed)
    return _fit_payload(payload, flow, seed)


def identify_application_payload(
    payload: bytes,
    transport: Optional[str] = None,
    port: Optional[int] = None,
) -> Optional[Tuple[ApplicationProfile, ApplicationFlow]]:
    """Identify a profile from visible protocol metadata in a request.

    The legacy marker is accepted for captures produced by older Fluxgen
    versions, but new traffic is identified through Host/SNI, protocol client
    identifiers, banners, or protocol-specific metadata.
    """
    if not payload:
        return None
    def matching_flow(profile: ApplicationProfile):
        return next((
            flow for flow in profile.flows
            if (transport is None or flow.transport == transport)
            and (port is None or port in flow.ports)
        ), None)

    # DNS names are length-delimited rather than plain-text fields.
    query_name = _dns_query_name(payload) if port == 53 else None
    if query_name:
        for profile in APPLICATION_PROFILES.values():
            if query_name == profile.hostname:
                flow = matching_flow(profile)
                if flow is not None:
                    return profile, flow

    # Host names are the strongest identity because they are bounded protocol
    # fields in both HTTP and TLS SNI.  Check them before profile-name tokens
    # so ``video`` cannot steal a ``video-on-demand`` request.
    coap_path = _coap_path(payload) if transport == "udp" and port in {5683, 5684} else None
    if coap_path:
        for profile in APPLICATION_PROFILES.values():
            if coap_path == profile.name:
                flow = matching_flow(profile)
                if flow is not None:
                    return profile, flow

    for profile in sorted(APPLICATION_PROFILES.values(), key=lambda item: len(item.hostname), reverse=True):
        if profile.hostname.encode("ascii") in payload:
            flow = matching_flow(profile)
            if flow is not None:
                return profile, flow

    # Other protocol families carry the profile in a bounded application
    # field: MQTT client id, SSH banner, RTP media marker, APP fallback, or
    # SIP/IPv4 service metadata.  Avoid unbounded substring matches.
    for profile in APPLICATION_PROFILES.values():
        name = profile.name.encode("ascii")
        encoded = _encoded_name(profile)
        markers = (
            b"fluxgen-" + name + b"-",
            b"Fluxgen_" + name,
            b"APP/1.0 " + name + b" ",
            b"/" + name + b"/",
            b"/" + encoded + b"/",
            encoded + b"/",
            b"[" + name + b"]",
            b"cn=" + name,
        )
        if any(marker in payload for marker in markers):
            flow = matching_flow(profile)
            if flow is not None:
                return profile, flow

    # If the transport/port tuple is exclusive in the catalog, it is itself
    # a valid protocol discriminator (for example NTP/123 or Modbus/502).
    # Do not use this fallback for shared ports such as HTTPS/443.
    port_candidates = [
        (profile, flow)
        for profile in APPLICATION_PROFILES.values()
        for flow in profile.flows
        if (transport is None or flow.transport == transport)
        and (port is None or port in flow.ports)
    ]
    candidate_profiles = {profile.name for profile, _ in port_candidates}
    if len(candidate_profiles) == 1 and port_candidates:
        return port_candidates[0]

    # Backward-compatible support for pre-signature synthetic captures.
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
    identified = identify_application_payload(payload, transport=transport, port=port)
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
    request_payload: bytes = b"",
) -> bytes:
    """Build a protocol-native response for a previously identified flow."""
    seed = f"response:{profile.name}:{flow.name}:{request_index}".encode("utf-8")
    if flow.signature == "http":
        body = (f'{{"application":"{profile.name}","status":"ok"}}').encode("utf-8")
        return _fit_payload((
            b"HTTP/1.1 200 OK\r\n"
            b"Server: Fluxgen/2\r\n"
            b"Content-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\nConnection: keep-alive\r\n\r\n".encode("ascii")
            + body
        ), flow, seed)
    if flow.signature == "tls":
        return _fit_payload(_tls_server_hello(profile, seed), flow, seed)
    if flow.signature == "dns":
        return _fit_payload(_dns_response(profile, seed, request_payload), flow, seed)
    if flow.signature == "mqtt":
        return _fit_payload(b"\x20\x02\x00\x00", flow, seed)
    if flow.signature == "sip":
        return _fit_payload(_sip_response(profile), flow, seed)
    if flow.signature == "rtp":
        return _fit_payload(_rtp_packet(profile, request_index, seed, response=True), flow, seed)
    if flow.signature == "ssh":
        return _fit_payload(f"SSH-2.0-FluxgenResponder_{profile.name}\r\n".encode("ascii"), flow, seed)
    if flow.signature == "ntp":
        return _fit_payload(_ntp_packet(seed, response=True), flow, seed)
    if flow.signature == "ike":
        return _fit_payload(_ike_init(profile, seed, response=True), flow, seed)
    if flow.signature == "kerberos":
        return _fit_payload(_kerberos_request(profile, seed, response=True), flow, seed)
    if flow.signature == "tacacs":
        return _fit_payload(_tacacs_packet(profile, seed, response=True), flow, seed)
    if flow.signature == "rdp":
        return _fit_payload(_rdp_request(profile, response=True), flow, seed)
    if flow.signature == "vnc":
        return _fit_payload(_vnc_banner(profile, response=True), flow, seed)
    if flow.signature == "game":
        return _fit_payload(_game_packet(profile, request_index, seed, response=True), flow, seed)
    if flow.signature == "bittorrent":
        return _fit_payload(_bittorrent_handshake(profile, seed, response=True), flow, seed)
    if flow.signature == "dhcp":
        return _fit_payload(_dhcp_offer(profile, seed), flow, seed)
    if flow.signature == "coap":
        return _fit_payload(_coap_response(profile, request_index), flow, seed)
    if flow.signature == "modbus":
        return _fit_payload(_modbus_response(request_index), flow, seed)
    if flow.signature == "opcua":
        return _fit_payload(_opcua_ack(profile), flow, seed)
    if flow.signature == "bacnet":
        return _fit_payload(_bacnet_i_am(profile), flow, seed)
    if flow.signature == "ldap":
        return _fit_payload(_ldap_bind_response(), flow, seed)
    if flow.signature == "radius":
        return _fit_payload(_radius_access_accept(seed), flow, seed)
    if flow.signature == "snmp":
        return _fit_payload(_snmp_response(profile), flow, seed)
    if flow.signature == "syslog":
        return _fit_payload(_syslog_message(profile, request_index, response=True), flow, seed)
    if flow.signature in {"postgresql", "mysql", "mssql", "oracle", "redis", "mongodb", "kafka", "amqp"}:
        return _fit_payload(_database_response(profile, flow.signature, request_index), flow, seed)
    return _fit_payload(_raw_application_response(profile, flow, seed), flow, seed)


def application_profile_count() -> int:
    """Return the number of built-in application profiles."""
    return len(APPLICATION_PROFILES)
