from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from iot_guard.capture import PacketParser


def test_packet_parser_decodes_raw_ethernet_frame():
    frame = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="192.168.50.2", dst="1.1.1.1", ttl=64)
        / TCP(sport=50000, dport=443, flags="S")
    )

    observation = PacketParser().parse(Raw(load=bytes(frame)))

    assert observation is not None
    assert observation.src_mac == "02:00:00:00:00:01"
    assert observation.dst_mac == "02:00:00:00:00:02"
    assert observation.src_ip == "192.168.50.2"
    assert observation.dst_port == 443
    assert observation.packet_size == len(frame)