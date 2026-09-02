"""
Configuration loading and merging helpers.
"""

from __future__ import annotations

import json
import pathlib
import ipaddress
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple

from .applications import normalize_application_names


@dataclass
class RuntimeConfig:
    interface: str
    dst: str = ""
    clients: int = 1
    subnet_pool: Optional[str] = None
    dest_subnet: Optional[str] = None
    ip_version: int = 4
    dport: Optional[int] = None
    sport: Optional[int] = None
    proto: str = "tcp"
    flags: str = "S"
    interval: float = 0.1
    count: int = 1
    payload: Optional[str] = None
    data_size: Optional[int] = None
    payload_hex: bool = False
    flood: bool = False
    beast: bool = False
    fuzz: bool = False
    fuzz_seed: Optional[int] = None
    fuzz_mutations: int = 1
    duration: float = 0.0
    rand_source: bool = False
    rand_dest: bool = False
    ttl: int = 64
    tos: int = 0
    ip_id: Optional[int] = None
    frag: bool = False
    frag_size: Optional[int] = None
    frag_mode: str = "fixed"
    icmp_type: int = 8
    icmp_code: int = 0
    dry_run: bool = False
    pcap_out: Optional[str] = None
    verbose: bool = False
    quiet: bool = False
    client_start_index: Optional[int] = None
    application: Tuple[str, ...] = ()
    mode: str = "client"
    bidirectional: bool = False
    response_timeout: float = 1.0
    session_timeout: float = 300.0
    max_sessions: int = 10000
    extra: Dict[str, Any] = field(default_factory=dict)


def load_config_file(path: str) -> Dict[str, Any]:
    """
    Load a JSON or YAML config file. YAML is optional.
    """
    config_path = pathlib.Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    text = config_path.read_text()
    if config_path.suffix.lower() in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise RuntimeError("pyyaml is required to read YAML configs") from exc

        data = yaml.safe_load(text) or {}
    else:
        data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("Config file must define a mapping at the top level")
    return data


def merge_config(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """
    Combine two config dictionaries, keeping override values when provided.
    """
    merged = dict(base)
    for key, value in override.items():
        if value is None:
            continue
        merged[key] = value
    return merged


def build_runtime_config(data: Dict[str, Any]) -> RuntimeConfig:
    """
    Normalize dictionary input into a RuntimeConfig.
    """
    if "interface" not in data or not data.get("interface"):
        raise ValueError("Missing required option: interface")
    mode = str(data.get("mode", "client") or "client").lower()
    if mode not in {"client", "server"}:
        raise ValueError("mode must be one of: client, server")
    if mode == "client" and not data.get("dst") and not data.get("dest_subnet"):
        raise ValueError("Provide dst or dest_subnet to target traffic")

    clients = _as_int(data.get("clients"), default=1)
    if clients <= 0:
        raise ValueError("clients must be a positive integer")

    raw_client_start_index = data.get("client_start_index")
    client_start_index = (
        None
        if raw_client_start_index is None
        else _maybe_int(raw_client_start_index)
    )
    if raw_client_start_index is not None and client_start_index is None:
        raise ValueError("client_start_index must be an integer")
    if client_start_index is not None and client_start_index <= 0:
        raise ValueError("client_start_index must be a positive integer")

    application = normalize_application_names(data.get("application"))
    bidirectional = bool(data.get("bidirectional", False))
    if mode == "server" and bidirectional:
        raise ValueError("bidirectional mode is only valid with client mode")
    if bidirectional and (bool(data.get("beast", False)) or bool(data.get("fuzz", False))):
        raise ValueError("bidirectional mode cannot be combined with --beast or --fuzz")
    if application:
        conflicts = [
            key for key in ("proto", "flags", "payload", "data_size", "beast")
            if key in data and data.get(key) not in (None, False, "")
        ]
        if conflicts:
            rendered = ", ".join(f"--{key.replace('_', '-')}" for key in conflicts)
            raise ValueError(f"Application profiles control packet profiles; remove: {rendered}")

    duration = _as_float(data.get("duration"), default=0.0)
    if duration < 0:
        raise ValueError("time must be zero or a positive number of seconds")
    response_timeout = _as_float(data.get("response_timeout"), default=1.0)
    if response_timeout <= 0:
        raise ValueError("response_timeout must be positive")
    session_timeout = _as_float(data.get("session_timeout"), default=300.0)
    if session_timeout <= 0:
        raise ValueError("session_timeout must be positive")
    max_sessions = _as_int(data.get("max_sessions"), default=10000)
    if max_sessions <= 0:
        raise ValueError("max_sessions must be positive")

    beast = bool(data.get("beast", False))
    if beast:
        conflicts = [
            key for key in ("proto", "payload", "data_size", "frag")
            if key in data and data.get(key) not in (None, False, "")
        ]
        if conflicts:
            rendered = ", ".join(f"--{key.replace('_', '-')}" for key in conflicts)
            raise ValueError(f"Beast mode controls packet profiles; remove: {rendered}")

    count = _as_int(data.get("count"), default=0 if beast or mode == "server" else 1)
    if count < 0:
        raise ValueError("count must be zero or a positive integer")

    # Validate ports
    dport = _maybe_int(data.get("dport"))
    if dport is not None and not (0 <= dport <= 65535):
        raise ValueError(f"Invalid destination port: {dport} (must be 0-65535)")
    sport = _maybe_int(data.get("sport"))
    if sport is not None and not (0 <= sport <= 65535):
        raise ValueError(f"Invalid source port: {sport} (must be 0-65535)")

    # Validate TCP flags
    flags = str(data.get("flags", "S") or "S")
    if not _validate_tcp_flags(flags):
        raise ValueError(f"Invalid TCP flags: {flags} (use S,A,F,P,R,U)")

    # Validate ICMP type and code
    icmp_type = _as_int(data.get("icmp_type"), default=8)
    if not (0 <= icmp_type <= 255):
        raise ValueError(f"Invalid ICMP type: {icmp_type} (must be 0-255)")
    icmp_code = _as_int(data.get("icmp_code"), default=0)
    if not (0 <= icmp_code <= 255):
        raise ValueError(f"Invalid ICMP code: {icmp_code} (must be 0-255)")

    # Validate protocol
    proto = str(data.get("proto", "tcp") or "tcp").lower()
    valid_protocols = {
        "tcp", "udp", "icmp", "igmp", "gre", "esp", "ah", "sctp",
        "arp", "vrrp", "ospf",
    }
    if proto not in valid_protocols:
        raise ValueError(f"Invalid protocol: {proto} (must be one of {', '.join(sorted(valid_protocols))})")
    if bidirectional and not application and proto not in {"tcp", "udp", "icmp"}:
        raise ValueError("bidirectional mode supports tcp, udp, and icmp traffic")

    ip_version = _resolve_ip_version(data)
    if ip_version == 6 and proto in {"arp", "igmp"}:
        raise ValueError(f"{proto.upper()} is only supported for IPv4")

    raw_fuzz_mutations = data.get("fuzz_mutations")
    fuzz_mutations = 1 if raw_fuzz_mutations is None else _maybe_int(raw_fuzz_mutations)
    if fuzz_mutations is None or fuzz_mutations <= 0:
        raise ValueError("fuzz_mutations must be a positive integer")
    raw_fuzz_seed = data.get("fuzz_seed")
    fuzz_seed = None if raw_fuzz_seed is None else _maybe_int(raw_fuzz_seed)
    if raw_fuzz_seed is not None and fuzz_seed is None:
        raise ValueError("fuzz_seed must be an integer")

    data_size = _maybe_int(data.get("data_size"))
    if data_size is not None and data_size <= 0:
        raise ValueError("data_size must be a positive integer")
    frag_mode = str(data.get("frag_mode", "fixed") or "fixed").lower()
    if frag_mode not in {"fixed", "random"}:
        raise ValueError("frag_mode must be one of: fixed, random")
    if data.get("payload") is not None and data_size:
        raise ValueError("Specify either payload or data_size, not both")

    return RuntimeConfig(
        interface=data["interface"],
        dst=str(data.get("dst", "") or ""),
        clients=clients,
        client_start_index=client_start_index,
        subnet_pool=data.get("subnet_pool"),
        dest_subnet=data.get("dest_subnet"),
        ip_version=ip_version,
        dport=dport,
        sport=sport,
        proto=proto,
        flags=flags,
        interval=_as_float(data.get("interval"), default=0.1),
        count=count,
        payload=data.get("payload"),
        data_size=data_size,
        payload_hex=bool(data.get("payload_hex", False)),
        flood=bool(data.get("flood", False)),
        beast=beast,
        fuzz=bool(data.get("fuzz", False)),
        fuzz_seed=fuzz_seed,
        fuzz_mutations=fuzz_mutations,
        duration=duration,
        rand_source=bool(data.get("rand_source", False)),
        rand_dest=bool(data.get("rand_dest", False)),
        ttl=_as_int(data.get("ttl"), default=64),
        tos=_as_int(data.get("tos"), default=0),
        ip_id=_maybe_int(data.get("ip_id")),
        frag=bool(data.get("frag", False)),
        frag_size=_maybe_int(data.get("frag_size")),
        frag_mode=frag_mode,
        icmp_type=icmp_type,
        icmp_code=icmp_code,
        dry_run=bool(data.get("dry_run", False)),
        pcap_out=data.get("pcap_out"),
        verbose=bool(data.get("verbose", False)),
        quiet=bool(data.get("quiet", False)),
        extra={k: v for k, v in data.items() if k not in _known_keys()},
        application=application,
        mode=mode,
        bidirectional=bidirectional,
        response_timeout=response_timeout,
        session_timeout=session_timeout,
        max_sessions=max_sessions,
    )


def _maybe_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _known_keys() -> set:
    return {
        "interface",
        "dst",
        "clients",
        "client_start_index",
        "application",
        "mode",
        "bidirectional",
        "response_timeout",
        "session_timeout",
        "max_sessions",
        "subnet_pool",
        "dest_subnet",
        "ip_version",
        "dport",
        "sport",
        "proto",
        "flags",
        "interval",
        "count",
        "payload",
        "data_size",
        "payload_hex",
        "flood",
        "beast",
        "fuzz",
        "fuzz_seed",
        "fuzz_mutations",
        "duration",
        "rand_source",
        "rand_dest",
        "ttl",
        "tos",
        "ip_id",
        "frag",
        "frag_size",
        "frag_mode",
        "icmp_type",
        "icmp_code",
        "dry_run",
        "pcap_out",
        "verbose",
        "quiet",
    }


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _validate_tcp_flags(flags: str) -> bool:
    """
    Validate TCP flags string. Accepts hping3-style flags: S,A,F,P,R,U.
    """
    valid_flags = set("SAFPRU")
    return all(c in valid_flags for c in flags.upper())


def _resolve_ip_version(data: Dict[str, Any]) -> int:
    """
    Resolve IP version from config with support for auto-detection.
    """
    raw = data.get("ip_version", "auto")
    if isinstance(raw, int):
        raw_str = str(raw)
    else:
        raw_str = str(raw or "auto").lower()

    if raw_str in {"4", "ipv4"}:
        desired = 4
    elif raw_str in {"6", "ipv6"}:
        desired = 6
    elif raw_str in {"auto", ""}:
        desired = 0
    else:
        raise ValueError("ip_version must be one of: 4, 6, auto")

    detected: Optional[int] = None
    dst = data.get("dst")
    dest_subnet = data.get("dest_subnet")
    for target in (dst, dest_subnet):
        if not target:
            continue
        try:
            net = ipaddress.ip_network(target, strict=False)
            detected = net.version
            break
        except (ValueError, TypeError):
            try:
                detected = ipaddress.ip_address(target).version  # type: ignore[arg-type]
                break
            except (ValueError, TypeError):
                continue

    if desired and detected and desired != detected:
        raise ValueError(f"ip_version {desired} does not match provided address family {detected}")
    if desired:
        return desired
    if str(data.get("mode", "client") or "client").lower() == "server":
        return 0
    return detected or 4
