"""Independent dual-stack responder for Fluxgen traffic.

The responder is deliberately implemented at Ethernet/IP level.  It can run
on a different machine from the sender and still answer spoofed client
identities because it does not depend on the host TCP/IP socket table.
"""

from __future__ import annotations

import ipaddress
import random
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from scapy.all import (  # type: ignore
    ARP,
    AsyncSniffer,
    Ether,
    ICMP,
    IP,
    IPv6,
    PcapWriter,
    Raw,
    SCTP,
    SCTPChunkData,
    TCP,
    UDP,
    sendp,
)
from scapy.layers.inet6 import ICMPv6EchoReply, ICMPv6EchoRequest  # type: ignore

from .applications import (
    ApplicationFlow,
    ApplicationProfile,
    build_application_response_payload,
    select_responder_flow,
)
from .config import RuntimeConfig
from .netinfo import InterfaceInfo, get_interface_infos


@dataclass
class ResponderStats:
    """Counters for received and generated responder traffic."""

    received: int = 0
    responded: int = 0
    ignored: int = 0
    sent: int = 0
    errors: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def bump(self, field_name: str, count: int = 1) -> None:
        with self._lock:
            setattr(self, field_name, getattr(self, field_name) + count)


@dataclass
class TCPSession:
    server_seq: int
    client_next_seq: int
    server_next_seq: int
    requests: int = 0


class Responder:
    """Capture and answer Fluxgen traffic addressed to interface IPs."""

    def __init__(self, cfg: RuntimeConfig):
        self.cfg = cfg
        self.stop_event = threading.Event()
        self.stats = ResponderStats()
        self.interface_infos: List[InterfaceInfo] = []
        self.listen_addresses: Dict[str, InterfaceInfo] = {}
        self.sessions: Dict[Tuple[str, str, int, str, int], TCPSession] = {}
        self.session_times: Dict[Tuple[str, str, int, str, int], float] = {}
        self.session_lock = threading.Lock()
        self.writer: Optional[PcapWriter] = None
        self.writer_lock = threading.Lock()
        self.sniffer = None
        self.deadline: Optional[float] = None

    def run(self, pcap_writer: Optional[PcapWriter] = None) -> ResponderStats:
        family = self.cfg.ip_version if self.cfg.ip_version in (4, 6) else 0
        self.interface_infos = get_interface_infos(self.cfg.interface, family)
        self.listen_addresses = {
            str(info.address.ip): info for info in self.interface_infos
        }
        writer = pcap_writer
        created_writer = False
        if writer is None and self.cfg.pcap_out:
            writer = PcapWriter(self.cfg.pcap_out, append=True, sync=True)
            created_writer = True
        self.writer = writer
        self.deadline = (
            time.monotonic() + self.cfg.duration
            if self.cfg.duration > 0
            else None
        )

        try:
            self.sniffer = AsyncSniffer(
                iface=self.cfg.interface,
                filter="arp or ip or ip6",
                prn=self._on_packet,
                store=False,
            )
            self.sniffer.start()
            while not self.stop_event.is_set() and not self._duration_expired():
                self.stop_event.wait(timeout=0.1)
        except KeyboardInterrupt:
            self.stop_event.set()
        finally:
            self.stop_event.set()
            if self.sniffer is not None:
                try:
                    self.sniffer.stop()
                except (OSError, RuntimeError):
                    pass
            if created_writer and writer:
                writer.close()
        return self.stats

    def stop(self) -> None:
        self.stop_event.set()

    def _on_packet(self, packet) -> None:
        self.stats.bump("received")
        if self.writer:
            with self.writer_lock:
                self.writer.write(packet)
        try:
            responses = self.build_responses(packet)
        except (AttributeError, IndexError, ValueError, OSError):
            self.stats.bump("errors")
            return
        if not responses:
            self.stats.bump("ignored")
            return
        self.stats.bump("responded", len(responses))
        if self.cfg.dry_run:
            for response in responses:
                print(response.summary())
            return
        for response in responses:
            try:
                if self.writer:
                    with self.writer_lock:
                        self.writer.write(response)
                sendp(response, iface=self.cfg.interface, verbose=0)
                self.stats.bump("sent")
            except (OSError, PermissionError):
                self.stats.bump("errors")

    def build_responses(self, packet) -> List:
        """Return protocol responses without transmitting them."""
        if not packet.haslayer(Ether):
            return []
        if packet.haslayer(ARP):
            return self._arp_response(packet)
        if packet.haslayer(IP):
            if str(packet[IP].dst) not in self.listen_addresses:
                return []
            if packet.haslayer(TCP):
                return self._tcp_response(packet, packet[IP], packet[TCP])
            if packet.haslayer(UDP):
                return self._udp_response(packet, packet[IP], packet[UDP])
            if packet.haslayer(ICMP):
                return self._icmp_response(packet, packet[IP])
            if packet.haslayer(SCTP):
                return self._sctp_response(packet, packet[IP], packet[SCTP])
            return []
        if packet.haslayer(IPv6):
            if str(packet[IPv6].dst) not in self.listen_addresses:
                return []
            if packet.haslayer(TCP):
                return self._tcp_response(packet, packet[IPv6], packet[TCP])
            if packet.haslayer(UDP):
                return self._udp_response(packet, packet[IPv6], packet[UDP])
            if packet.haslayer(ICMPv6EchoRequest):
                return self._icmpv6_response(packet, packet[IPv6])
            if packet.haslayer(SCTP):
                return self._sctp_response(packet, packet[IPv6], packet[SCTP])
        return []

    def _server_info(self, dst: str) -> InterfaceInfo:
        return self.listen_addresses[dst]

    def _ether_reply(self, packet, server: InterfaceInfo) -> Ether:
        return Ether(src=server.mac, dst=packet[Ether].src)

    def _ip_reply(self, ip_layer, server_ip: str):
        if isinstance(ip_layer, IPv6):
            return IPv6(src=server_ip, dst=str(ip_layer.src), hlim=64, tc=ip_layer.tc)
        return IP(src=server_ip, dst=str(ip_layer.src), ttl=64, tos=ip_layer.tos)

    def _arp_response(self, packet) -> List:
        arp = packet[ARP]
        server = self.listen_addresses.get(str(arp.pdst))
        if server is None or arp.op not in (1, "who-has"):
            return []
        return [
            self._ether_reply(packet, server)
            / ARP(
                op=2,
                hwsrc=server.mac,
                psrc=str(arp.pdst),
                hwdst=arp.hwsrc,
                pdst=arp.psrc,
            )
        ]

    @staticmethod
    def _tcp_key(ip_layer, tcp) -> Tuple[str, str, int, str, int]:
        return (
            str(ip_layer.dst),
            str(ip_layer.src),
            int(tcp.dport),
            str(ip_layer.src),
            int(tcp.sport),
        )

    def _tcp_response(self, packet, ip_layer, tcp) -> List:
        server = self._server_info(str(ip_layer.dst))
        key = self._tcp_key(ip_layer, tcp)
        flags = str(tcp.flags)
        payload = bytes(tcp.payload) if tcp.payload else b""
        client_seq = int(tcp.seq)
        with self.session_lock:
            session = self.sessions.get(key)
            if session and time.monotonic() - self.session_times.get(key, 0) > self.cfg.session_timeout:
                self.sessions.pop(key, None)
                self.session_times.pop(key, None)
                session = None
            if "S" in flags and "A" not in flags:
                while len(self.sessions) >= self.cfg.max_sessions and self.session_times:
                    oldest_key = min(self.session_times, key=self.session_times.get)
                    self.sessions.pop(oldest_key, None)
                    self.session_times.pop(oldest_key, None)
                server_seq = random.randint(0, 2**32 - 1)
                session = TCPSession(
                    server_seq=server_seq,
                    client_next_seq=client_seq + 1,
                    server_next_seq=server_seq + 1,
                )
                self.sessions[key] = session
                self.session_times[key] = time.monotonic()
                response = self._ether_reply(packet, server) / self._ip_reply(ip_layer, str(ip_layer.dst)) / TCP(
                    sport=int(tcp.dport),
                    dport=int(tcp.sport),
                    flags="SA",
                    seq=server_seq,
                    ack=client_seq + 1,
                )
                return [response]

            if session is None:
                # Support the legacy stateless sender by acknowledging its
                # payload even when no SYN was observed.
                server_seq = random.randint(0, 2**32 - 1)
                session = TCPSession(
                    server_seq=server_seq,
                    client_next_seq=client_seq,
                    server_next_seq=server_seq,
                )
                self.sessions[key] = session
            self.session_times[key] = time.monotonic()

            consumed = len(payload) + (1 if "F" in flags else 0)
            if consumed:
                session.client_next_seq = max(session.client_next_seq, client_seq + consumed)
                session.requests += 1
                flow = self._flow("tcp", int(tcp.dport), payload)
                response_payload = self._response_payload(flow, session.requests, payload)
                response_flags = "FA" if "F" in flags else "PA" if response_payload else "A"
                response = self._ether_reply(packet, server) / self._ip_reply(ip_layer, str(ip_layer.dst)) / TCP(
                    sport=int(tcp.dport),
                    dport=int(tcp.sport),
                    flags=response_flags,
                    seq=session.server_next_seq,
                    ack=session.client_next_seq,
                )
                if response_payload and "F" not in flags:
                    response = response / Raw(load=response_payload)
                    session.server_next_seq += len(response_payload)
                if "F" in flags:
                    session.server_next_seq += 1
                return [response]
        return []

    def _udp_response(self, packet, ip_layer, udp) -> List:
        server = self._server_info(str(ip_layer.dst))
        payload = bytes(udp.payload) if udp.payload else b""
        flow = self._flow("udp", int(udp.dport), payload)
        response_payload = self._response_payload(flow, 0, payload) or b"APP/1.0 200 fluxgen\r\n\r\n"
        return [
            self._ether_reply(packet, server)
            / self._ip_reply(ip_layer, str(ip_layer.dst))
            / UDP(sport=int(udp.dport), dport=int(udp.sport))
            / Raw(load=response_payload)
        ]

    def _icmp_response(self, packet, ip_layer) -> List:
        request = packet[ICMP]
        if int(request.type) != 8:
            return []
        server = self._server_info(str(ip_layer.dst))
        response = self._ether_reply(packet, server) / self._ip_reply(ip_layer, str(ip_layer.dst)) / ICMP(
            type=0,
            code=0,
            id=request.id,
            seq=request.seq,
        )
        if request.payload:
            response = response / request.payload.copy()
        return [response]

    def _icmpv6_response(self, packet, ip_layer) -> List:
        request = packet[ICMPv6EchoRequest]
        server = self._server_info(str(ip_layer.dst))
        response = self._ether_reply(packet, server) / self._ip_reply(ip_layer, str(ip_layer.dst)) / ICMPv6EchoReply(
            id=request.id,
            seq=request.seq,
        )
        if request.payload:
            response = response / request.payload.copy()
        return [response]

    def _sctp_response(self, packet, ip_layer, sctp) -> List:
        server = self._server_info(str(ip_layer.dst))
        response = self._ether_reply(packet, server) / self._ip_reply(ip_layer, str(ip_layer.dst)) / SCTP(
            sport=int(sctp.dport),
            dport=int(sctp.sport),
            tag=int(getattr(sctp, "tag", 0) or 0),
        ) / SCTPChunkData(data=b"fluxgen-response/sctp")
        return [response]

    def _flow(
        self,
        transport: str,
        port: int,
        payload: bytes,
    ) -> Optional[Tuple[ApplicationProfile, ApplicationFlow]]:
        return select_responder_flow(self.cfg.application, transport, port, payload)

    @staticmethod
    def _response_payload(
        flow: Optional[Tuple[ApplicationProfile, ApplicationFlow]],
        request_index: int,
        request_payload: bytes = b"",
    ) -> Optional[bytes]:
        if flow is None:
            return None
        profile, application_flow = flow
        return build_application_response_payload(
            profile, application_flow, request_index, request_payload
        )

    def _duration_expired(self) -> bool:
        return self.deadline is not None and time.monotonic() >= self.deadline
