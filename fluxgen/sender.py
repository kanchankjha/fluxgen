"""
Packet sending orchestration and client simulation.
"""

from __future__ import annotations

import ipaddress
import random
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Union

from scapy.all import PcapWriter, sendp  # type: ignore
from scapy.layers.l2 import getmacbyip  # type: ignore
from scapy.layers.inet6 import getmacbyip6  # type: ignore

from .config import RuntimeConfig
from .identity import Identity, generate_identities
from .netinfo import get_interface_info
from .packet_builder import build_frames


@dataclass
class SendStats:
    sent: int = 0
    errors: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def bump_sent(self, count: int = 1) -> None:
        with self._lock:
            self.sent += count

    def bump_error(self, count: int = 1) -> None:
        with self._lock:
            self.errors += count


class Simulator:
    """
    Orchestrates multi-threaded packet sending with simulated client identities.

    Creates worker threads for each simulated client, manages packet crafting
    and sending, collects statistics, and optionally writes to pcap files.
    """
    def __init__(self, cfg: RuntimeConfig):
        self.cfg = cfg
        self.stop_event = threading.Event()
        self.stats = SendStats()
        self.dest_mac_cache: Dict[str, str] = {}
        self.identities: List[Identity] = []
        self.writer: Optional[PcapWriter] = None

    def run(self, pcap_writer: Optional[PcapWriter] = None) -> SendStats:
        iface_info = get_interface_info(self.cfg.interface, self.cfg.ip_version)
        network = (
            ipaddress.ip_network(self.cfg.subnet_pool, strict=False)
            if self.cfg.subnet_pool
            else iface_info.address.network
        )
        excludes: List[str] = [str(iface_info.address.ip)]
        if iface_info.gateway:
            excludes.append(iface_info.gateway)

        self.identities = generate_identities(
            count=self.cfg.clients,
            network=network,
            exclude_ips=excludes,
            base_mac=iface_info.mac,
        )

        dest_pool = _build_dest_pool(self.cfg)
        if not dest_pool:
            raise ValueError("No destination IPs available to target")

        writer = pcap_writer
        created_writer = False
        if writer is None and self.cfg.pcap_out:
            writer = PcapWriter(self.cfg.pcap_out, append=True, sync=True)
            created_writer = True
        self.writer = writer

        try:
            workers = [
                threading.Thread(
                    target=self._client_loop,
                    args=(identity, dest_pool, writer),
                    daemon=True,
                    name=f"client-{idx}",
                )
                for idx, identity in enumerate(self.identities)
            ]
            reporter = threading.Thread(target=self._report_loop, daemon=True, name="stats")

            reporter.start()
            for worker in workers:
                worker.start()

            try:
                for worker in workers:
                    worker.join(timeout=60)  # Add timeout to prevent infinite hang
                    if worker.is_alive():
                        print(f"Warning: Worker thread {worker.name} did not exit cleanly", file=sys.stderr)
            except KeyboardInterrupt:
                self.stop_event.set()
                for worker in workers:
                    worker.join(timeout=5)  # Shorter timeout on interrupt
                    if worker.is_alive():
                        print(f"Warning: Worker thread {worker.name} still running after interrupt", file=sys.stderr)
        finally:
            self.stop_event.set()
            if created_writer and writer:
                writer.close()

        return self.stats

    def _client_loop(self, identity: Identity, dest_pool: Union[List[str], ipaddress._BaseNetwork], pcap_writer: Optional[PcapWriter]) -> None:
        count_limit = self.cfg.count if self.cfg.count > 0 else None
        sends = 0
        while not self.stop_event.is_set():
            dest_ip = _choose_dest_ip(self.cfg, dest_pool)
            chosen_identity = (
                random.choice(self.identities) if self.cfg.rand_source else identity
            )
            dest_mac = self._resolve_dest_mac(dest_ip)
            try:
                frames = build_frames(self.cfg, chosen_identity, dest_ip, dest_mac)
            except (ValueError, OSError, AttributeError) as e:
                self.stats.bump_error()
                if self.cfg.verbose:
                    print(f"Failed to craft packet for {dest_ip}: {e}", file=sys.stderr)
                sends += 1
                if count_limit and sends >= count_limit:
                    break
                continue

            if self.cfg.dry_run:
                for frame in frames:
                    print(frame.summary())
                return

            for frame in frames:
                try:
                    if pcap_writer:
                        pcap_writer.write(frame)
                    sendp(frame, iface=self.cfg.interface, verbose=0)
                    self.stats.bump_sent()
                except (OSError, PermissionError) as e:
                    self.stats.bump_error()
                    if self.cfg.verbose:
                        print(f"Send error for {dest_ip}: {e}", file=sys.stderr)

            sends += 1
            if count_limit and sends >= count_limit:
                break
            if not self.cfg.flood:
                time.sleep(max(self.cfg.interval, 0.0))

    def _resolve_dest_mac(self, dest_ip: str) -> str:
        """
        Resolve the destination MAC address for the given IP.
        Falls back to broadcast MAC if resolution fails.
        """
        if dest_ip in self.dest_mac_cache:
            return self.dest_mac_cache[dest_ip]
        if self.cfg.ip_version == 6:
            mac = getmacbyip6(dest_ip)
        else:
            mac = getmacbyip(dest_ip)
        if not mac:
            if self.cfg.verbose:
                print(f"Warning: MAC resolution failed for {dest_ip}, using broadcast MAC", file=sys.stderr)
            mac = "33:33:00:00:00:01" if self.cfg.ip_version == 6 else "ff:ff:ff:ff:ff:ff"
        self.dest_mac_cache[dest_ip] = mac
        return mac

    def _report_loop(self) -> None:
        """Periodically print statistics unless quiet mode is enabled."""
        if self.cfg.quiet:
            return
        while not self.stop_event.is_set():
            # Use wait() instead of sleep() for faster shutdown response
            if self.stop_event.wait(timeout=1.0):
                break
            print(f"sent={self.stats.sent} errors={self.stats.errors}")


def _build_dest_pool(cfg: RuntimeConfig) -> Union[List[str], ipaddress._BaseNetwork]:
    if cfg.rand_dest and cfg.dest_subnet:
        return ipaddress.ip_network(cfg.dest_subnet, strict=False)
    if cfg.dst:
        return [cfg.dst]
    return []


def _choose_dest_ip(cfg: RuntimeConfig, pool: Union[List[str], ipaddress._BaseNetwork]) -> str:
    if isinstance(pool, list):
        return random.choice(pool) if cfg.rand_dest and len(pool) > 1 else pool[0]
    # pool is an ip_network
    if pool.version == 4:
        hosts = list(pool.hosts())
        if not hosts:
            raise ValueError(f"No usable hosts in destination subnet {pool}")
        return str(random.choice(hosts))
    # IPv6 - sample randomly from the subnet (avoid network address when possible)
    max_offset = pool.num_addresses - 1
    if max_offset <= 0:
        return str(pool.network_address)
    return str(ipaddress.IPv6Address(int(pool.network_address) + random.randrange(1, max_offset + 1)))
