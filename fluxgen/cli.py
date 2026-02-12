"""
Command-line entrypoint for the traffic simulator.
"""

from __future__ import annotations

import argparse
import sys
from typing import Any, Dict, List, Optional

from .config import build_runtime_config, load_config_file, merge_config
from .sender import Simulator


def main(argv: Optional[List[str]] = None) -> int:
    args = _parse_args(argv)
    file_cfg: Dict[str, Any] = {}
    if args.config:
        file_cfg = load_config_file(args.config)

    cli_cfg = {k: v for k, v in vars(args).items() if k not in {"config"}}
    merged = merge_config(file_cfg, cli_cfg)
    cfg = build_runtime_config(merged)

    simulator = Simulator(cfg)
    stats = simulator.run()
    print(f"Finished: sent={stats.sent} errors={stats.errors}")
    return 0


def _parse_args(argv: Optional[List[str]]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="fluxgen",
        description="Simulate multiple clients sending hping3-like traffic",
    )
    parser.add_argument("--config", help="Optional YAML or JSON config file")
    parser.add_argument("--interface", help="Interface to send on (required)")
    parser.add_argument("--dst", help="Destination IP address (required unless using dest_subnet)")
    parser.add_argument("--dest-subnet", help="CIDR to randomize destination addresses")
    parser.add_argument("--clients", type=int, default=None, help="Number of simulated clients")
    parser.add_argument("--subnet-pool", help="CIDR pool for client IPs (defaults to interface subnet)")
    parser.add_argument("--ip-version", choices=["4", "6", "auto"], default=None, help="Force IPv4, IPv6, or auto-detect")
    parser.add_argument("--dport", type=int, help="Destination port for TCP/UDP/SCTP")
    parser.add_argument("--sport", type=int, help="Source port for TCP/UDP/SCTP")
    parser.add_argument("--proto", choices=["tcp", "udp", "icmp", "igmp", "gre", "esp", "ah", "sctp"], default=None, help="Protocol to send")
    parser.add_argument("--flags", default=None, help="TCP flags string (hping3 style)")
    parser.add_argument("--interval", type=float, default=None, help="Interval between sends in seconds")
    parser.add_argument("--count", type=int, default=None, help="Packets per client (0 for infinite)")
    parser.add_argument("--payload", help="Optional payload as string or hex when --payload-hex is set")
    parser.add_argument("--data-size", type=int, default=None, help="Generate default payload of N bytes when no payload is provided")
    parser.add_argument("--payload-hex", action="store_true", default=None, help="Treat payload as hex")
    parser.add_argument("--flood", action="store_true", default=None, help="Send as fast as possible")
    parser.add_argument("--rand-source", action="store_true", default=None, help="Randomize source identity per packet")
    parser.add_argument("--rand-dest", action="store_true", default=None, help="Randomize destination IP per packet")
    parser.add_argument("--ttl", type=int, default=None, help="IP TTL")
    parser.add_argument("--tos", type=int, default=None, help="IP TOS")
    parser.add_argument("--ip-id", type=int, help="IP identification field")
    parser.add_argument("--frag", action="store_true", default=None, help="Enable fragmentation")
    parser.add_argument("--frag-size", type=int, help="Fragment size in bytes")
    parser.add_argument("--frag-mode", choices=["fixed", "random"], default=None, help="Fragmentation mode: fixed size or random per send")
    parser.add_argument("--icmp-type", type=int, default=None, help="ICMP type (default echo request)")
    parser.add_argument("--icmp-code", type=int, default=None, help="ICMP code")
    parser.add_argument("--pcap-out", help="Optional path to write sent packets to a pcap file")
    parser.add_argument("--dry-run", action="store_true", default=None, help="Build packets but do not send")
    parser.add_argument("--verbose", action="store_true", default=None, help="Verbose errors")
    parser.add_argument("--quiet", action="store_true", default=None, help="Suppress periodic stats output")

    parsed = parser.parse_args(argv)
    return parsed


if __name__ == "__main__":
    sys.exit(main())
