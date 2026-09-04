"""
Packet sending orchestration and client simulation.
"""

from __future__ import annotations

import ipaddress
import queue
import random
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Union

from scapy.all import AsyncSniffer, ICMP, IP, IPv6, PcapWriter, TCP, UDP, sendp  # type: ignore
from scapy.layers.inet6 import ICMPv6EchoReply  # type: ignore
from scapy.layers.l2 import getmacbyip  # type: ignore
from scapy.layers.inet6 import getmacbyip6  # type: ignore

from .applications import select_application_profile
from .config import RuntimeConfig
from .identity import Identity, generate_identities
from .netinfo import get_interface_info
from .packet_builder import build_beast_profile, build_frames


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
        self.writer_lock = threading.Lock()
        self.deadline: Optional[float] = None
        self.response_queues: Dict[tuple, queue.Queue] = {}
        self.response_lock = threading.Lock()
        self.response_sniffer = None

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

        identity_kwargs = {
            "count": self.cfg.clients,
            "network": network,
            "exclude_ips": excludes,
            "base_mac": iface_info.mac,
        }
        if self.cfg.client_start_index is not None:
            identity_kwargs["start_index"] = self.cfg.client_start_index
        self.identities = generate_identities(**identity_kwargs)

        dest_pool = _build_dest_pool(self.cfg)
        if not dest_pool:
            raise ValueError("No destination IPs available to target")

        writer = pcap_writer
        created_writer = False
        if writer is None and self.cfg.pcap_out:
            writer = PcapWriter(self.cfg.pcap_out, append=True, sync=True)
            created_writer = True
        self.writer = writer
        raw_mtu = getattr(iface_info, "mtu", 1500)
        mtu = raw_mtu if isinstance(raw_mtu, int) and raw_mtu > 0 else 1500
        self.deadline = (
            time.monotonic() + self.cfg.duration
            if self.cfg.duration > 0
            else None
        )

        try:
            if self.cfg.bidirectional:
                self.response_sniffer = AsyncSniffer(
                    iface=self.cfg.interface,
                    filter="ip or ip6",
                    prn=self._on_response,
                    store=False,
                )
                self.response_sniffer.start()
            workers = [
                threading.Thread(
                    target=self._client_loop,
                    args=(identity, dest_pool, writer, idx, mtu),
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
                while any(worker.is_alive() for worker in workers):
                    # Give newly-started workers a chance to emit before a
                    # short duration expires, and avoid coupling orchestration
                    # polling to the per-packet sleep function.
                    if self.stop_event.wait(timeout=0.01):
                        break
                    if self._duration_expired():
                        self.stop_event.set()
                        break
            except KeyboardInterrupt:
                self.stop_event.set()
        finally:
            self.stop_event.set()
            if self.response_sniffer is not None:
                try:
                    self.response_sniffer.stop()
                except (OSError, RuntimeError):
                    pass
            shutdown_deadline = time.monotonic() + 5.0
            for worker in locals().get("workers", []):
                remaining = max(0.0, shutdown_deadline - time.monotonic())
                worker.join(timeout=remaining)
                if worker.is_alive():
                    print(f"Warning: Worker thread {worker.name} did not exit cleanly", file=sys.stderr)
            if "reporter" in locals():
                reporter.join(timeout=1.0)
            if created_writer and writer:
                writer.close()

        return self.stats

    def _client_loop(
        self,
        identity: Identity,
        dest_pool: Union[List[str], ipaddress._BaseNetwork],
        pcap_writer: Optional[PcapWriter],
        client_index: int = 0,
        mtu: int = 1500,
    ) -> None:
        count_limit = self.cfg.count if self.cfg.count > 0 else None
        sends = 0
        fuzz_rng = random.Random(
            None if self.cfg.fuzz_seed is None else self.cfg.fuzz_seed + client_index
        )
        while not self.stop_event.is_set():
            if self._duration_expired():
                self.stop_event.set()
                break
            dest_ip = _choose_dest_ip(self.cfg, dest_pool)
            chosen_identity = (
                random.choice(self.identities) if self.cfg.rand_source else identity
            )
            try:
                profile = None
                application_profile = select_application_profile(
                    self.cfg.application,
                    client_index,
                    sends,
                )
                if self.cfg.beast:
                    profile = build_beast_profile(
                        self.cfg.ip_version,
                        mtu,
                        sends,
                        client_index,
                        sport=self.cfg.sport,
                        dport=self.cfg.dport,
                    )
                application_flow = (
                    application_profile.flow_for(sends)
                    if application_profile
                    else None
                )
                wire_proto = (
                    profile.proto
                    if profile
                    else application_flow.transport
                    if application_flow
                    else self.cfg.proto
                )
                dest_mac = (
                    "ff:ff:ff:ff:ff:ff"
                    if wire_proto == "arp"
                    else self._resolve_dest_mac(dest_ip)
                )
                if self.cfg.bidirectional and not self.cfg.dry_run:
                    completed = self._run_bidirectional_transaction(
                        chosen_identity,
                        dest_ip,
                        dest_mac,
                        application_profile,
                        application_flow,
                        sends,
                        client_index,
                        pcap_writer,
                    )
                    if not completed:
                        self.stats.bump_error()
                    sends += 1
                    if count_limit and sends >= count_limit:
                        break
                    if not self.cfg.flood:
                        time.sleep(max(self.cfg.interval, 0.0))
                    continue
                if profile:
                    frames = build_frames(
                        self.cfg,
                        chosen_identity,
                        dest_ip,
                        dest_mac,
                        profile=profile,
                        fuzz_rng=fuzz_rng,
                        application_profile=application_profile,
                        application_index=sends,
                        client_index=client_index,
                    )
                else:
                    frames = build_frames(
                        self.cfg,
                        chosen_identity,
                        dest_ip,
                        dest_mac,
                        fuzz_rng=fuzz_rng,
                        application_profile=application_profile,
                        application_index=sends,
                        client_index=client_index,
                    )
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
                        with self.writer_lock:
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

    @staticmethod
    def _response_key(packet) -> Optional[tuple]:
        ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
        if ip_layer is None:
            return None
        if packet.haslayer(TCP):
            transport = packet[TCP]
            return ("tcp", str(ip_layer.src), str(ip_layer.dst), int(transport.sport), int(transport.dport))
        if packet.haslayer(UDP):
            transport = packet[UDP]
            return ("udp", str(ip_layer.src), str(ip_layer.dst), int(transport.sport), int(transport.dport))
        if packet.haslayer(ICMP) or packet.haslayer(ICMPv6EchoReply):
            return ("icmp", str(ip_layer.src), str(ip_layer.dst), 0, 0)
        return None

    def _on_response(self, packet) -> None:
        key = self._response_key(packet)
        if key is None:
            return
        with self.response_lock:
            response_queue = self.response_queues.get(key)
        if response_queue is not None:
            response_queue.put(packet)

    def _register_response(self, key: tuple) -> queue.Queue:
        response_queue: queue.Queue = queue.Queue()
        with self.response_lock:
            self.response_queues[key] = response_queue
        return response_queue

    def _unregister_response(self, key: tuple) -> None:
        with self.response_lock:
            self.response_queues.pop(key, None)

    def _transmit_frames(self, frames: List, dest_ip: str, pcap_writer: Optional[PcapWriter]) -> None:
        for frame in frames:
            try:
                if pcap_writer:
                    with self.writer_lock:
                        pcap_writer.write(frame)
                sendp(frame, iface=self.cfg.interface, verbose=0)
                self.stats.bump_sent()
            except (OSError, PermissionError) as exc:
                self.stats.bump_error()
                if self.cfg.verbose:
                    print(f"Send error for {dest_ip}: {exc}", file=sys.stderr)

    def _run_bidirectional_transaction(
        self,
        identity: Identity,
        dest_ip: str,
        dest_mac: str,
        application_profile,
        application_flow,
        packet_index: int,
        client_index: int,
        pcap_writer: Optional[PcapWriter],
    ) -> bool:
        """Run one wire-only transaction against an independent responder."""
        proto = application_flow.transport if application_flow else self.cfg.proto
        dport = (
            application_flow.port_for(packet_index)
            if application_flow and self.cfg.dport is None
            else self.cfg.dport
        )
        sport = self.cfg.sport or random.randint(1024, 65535)
        if proto in {"tcp", "udp"} and not dport:
            if self.cfg.verbose:
                print("Bidirectional TCP/UDP traffic requires a destination port", file=sys.stderr)
            return False

        key = (proto, dest_ip, str(identity.ip), int(dport or 0), int(sport or 0))
        response_queue = self._register_response(key)
        try:
            if proto == "tcp":
                client_seq = random.randint(0, 2**32 - 1)
                syn = build_frames(
                    self.cfg,
                    identity,
                    dest_ip,
                    dest_mac,
                    application_profile=application_profile,
                    application_index=packet_index,
                    client_index=client_index,
                    sport=sport,
                    dport=dport,
                    tcp_flags="S",
                    tcp_seq=client_seq,
                    tcp_ack=0,
                    include_application_payload=False,
                )
                self._transmit_frames(syn, dest_ip, pcap_writer)
                syn_ack = self._wait_for_response(response_queue)
                if syn_ack is None or not syn_ack.haslayer(TCP) or "S" not in str(syn_ack[TCP].flags):
                    return False
                server_seq = int(syn_ack[TCP].seq)
                client_next = client_seq + 1
                server_next = server_seq + 1
                request = build_frames(
                    self.cfg,
                    identity,
                    dest_ip,
                    dest_mac,
                    application_profile=application_profile,
                    application_index=packet_index,
                    client_index=client_index,
                    sport=sport,
                    dport=dport,
                    tcp_flags="PA" if application_profile or self.cfg.payload or self.cfg.data_size else "A",
                    tcp_seq=client_next,
                    tcp_ack=server_next,
                )
                self._transmit_frames(request, dest_ip, pcap_writer)
                request_length = sum(
                    len(bytes(frame[TCP].payload))
                    for frame in request
                    if frame.haslayer(TCP)
                )
                client_next += request_length
                response = self._wait_for_response(response_queue)
                if response is not None and response.haslayer(TCP):
                    response_tcp = response[TCP]
                    response_len = len(bytes(response_tcp.payload))
                    if response_len:
                        server_next = max(server_next, int(response_tcp.seq) + response_len)
                        ack = build_frames(
                            self.cfg,
                            identity,
                            dest_ip,
                            dest_mac,
                            application_index=packet_index,
                            client_index=client_index,
                            sport=sport,
                            dport=dport,
                            tcp_flags="A",
                            tcp_seq=client_next,
                            tcp_ack=server_next,
                            include_application_payload=False,
                        )
                        self._transmit_frames(ack, dest_ip, pcap_writer)
                fin = build_frames(
                    self.cfg,
                    identity,
                    dest_ip,
                    dest_mac,
                    application_index=packet_index,
                    client_index=client_index,
                    sport=sport,
                    dport=dport,
                    tcp_flags="FA",
                    tcp_seq=client_next,
                    tcp_ack=server_next,
                    include_application_payload=False,
                )
                self._transmit_frames(fin, dest_ip, pcap_writer)
                return response is not None

            frames = build_frames(
                self.cfg,
                identity,
                dest_ip,
                dest_mac,
                application_profile=application_profile,
                application_index=packet_index,
                client_index=client_index,
                sport=sport if proto == "udp" else None,
                dport=dport,
            )
            self._transmit_frames(frames, dest_ip, pcap_writer)
            response = self._wait_for_response(response_queue)
            return response is not None
        except (AttributeError, OSError, ValueError):
            return False
        finally:
            self._unregister_response(key)

    def _wait_for_response(self, response_queue: queue.Queue):
        try:
            return response_queue.get(timeout=self.cfg.response_timeout)
        except queue.Empty:
            return None

    def _duration_expired(self) -> bool:
        return self.deadline is not None and time.monotonic() >= self.deadline

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
