"""Tests for the independent dual-stack responder."""

from types import SimpleNamespace

from scapy.all import ARP, Ether, ICMP, IP, IPv6, Raw, TCP, UDP
from scapy.layers.inet6 import ICMPv6EchoReply, ICMPv6EchoRequest

from fluxgen.config import RuntimeConfig
from fluxgen.responder import Responder


def make_responder():
    responder = Responder(RuntimeConfig(interface="eth1", mode="server", ip_version=0))
    responder.listen_addresses = {
        "192.0.2.10": SimpleNamespace(mac="02:00:00:00:00:10"),
        "2001:db8::10": SimpleNamespace(mac="02:00:00:00:00:10"),
    }
    return responder


def test_server_ignores_traffic_not_destined_to_interface():
    responder = make_responder()
    packet = Ether(src="02:00:00:00:00:20") / IP(src="192.0.2.20", dst="192.0.2.99") / UDP(
        sport=1234, dport=443
    ) / Raw(b"request")
    assert responder.build_responses(packet) == []


def test_server_answers_tcp_syn_and_application_payload():
    responder = make_responder()
    base = Ether(src="02:00:00:00:00:20", dst="02:00:00:00:00:10") / IP(
        src="192.0.2.20", dst="192.0.2.10"
    )
    syn = base / TCP(sport=1234, dport=443, flags="S", seq=100)
    syn_ack = responder.build_responses(syn)[0]
    assert syn_ack[Ether].dst == base[Ether].src
    assert syn_ack[Ether].src == base[Ether].dst
    assert syn_ack[IP].src == "192.0.2.10"
    assert syn_ack[IP].dst == "192.0.2.20"
    assert syn_ack[TCP].flags == "SA"
    assert syn_ack[TCP].ack == 101

    request = base / TCP(
        sport=1234, dport=443, flags="PA", seq=101, ack=syn_ack[TCP].seq + 1
    ) / Raw(b"fluxgen/webex/control/request")
    response = responder.build_responses(request)[0]
    assert response[TCP].flags == "PA"
    assert response[TCP].ack == 101 + len(request[TCP].payload)
    assert bytes(response[Raw].load).startswith(b"fluxgen-response/webex/")


def test_server_answers_udp_and_icmp():
    responder = make_responder()
    base = Ether(src="02:00:00:00:00:20", dst="02:00:00:00:00:10") / IP(
        src="192.0.2.20", dst="192.0.2.10"
    )
    udp = base / UDP(sport=1234, dport=443) / Raw(b"fluxgen/webex/control/request")
    udp_response = responder.build_responses(udp)[0]
    assert udp_response[UDP].sport == 443
    assert udp_response[UDP].dport == 1234
    assert bytes(udp_response[Raw].load).startswith(b"fluxgen-response/webex/")

    echo = base / ICMP(type=8, id=7, seq=3) / Raw(b"ping")
    echo_response = responder.build_responses(echo)[0]
    assert echo_response[ICMP].type == 0
    assert echo_response[ICMP].id == 7
    assert bytes(echo_response[Raw].load) == b"ping"


def test_server_answers_ipv6_echo():
    responder = make_responder()
    packet = Ether(src="02:00:00:00:00:20", dst="02:00:00:00:00:10") / IPv6(
        src="2001:db8::20", dst="2001:db8::10"
    ) / ICMPv6EchoRequest(id=9, seq=4) / Raw(b"v6")
    response = responder.build_responses(packet)[0]
    assert response[IPv6].src == "2001:db8::10"
    assert response[IPv6].dst == "2001:db8::20"
    assert response.haslayer(ICMPv6EchoReply)
    assert response[ICMPv6EchoReply].id == 9


def test_server_answers_arp_request():
    responder = make_responder()
    packet = Ether(src="02:00:00:00:00:20", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1,
        hwsrc="02:00:00:00:00:20",
        psrc="192.0.2.20",
        pdst="192.0.2.10",
    )
    response = responder.build_responses(packet)[0]
    assert response[ARP].op == 2
    assert response[ARP].psrc == "192.0.2.10"
    assert response[ARP].pdst == "192.0.2.20"
