from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Deauth, Dot11Elt, RadioTap
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from iot_guard.capture import PacketParser, WirelessObservation, WirelessParser
from iot_guard.wireless import WirelessAttackDetector


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


def test_wireless_parser_decodes_monitor_beacon():
    frame = (
        RadioTap(
            present="Channel+dBm_AntSignal",
            dBm_AntSignal=-42,
            ChannelFrequency=2437,
            ChannelFlags=0x00A0,
        )
        / Dot11(
            type=0,
            subtype=8,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2="02:00:00:00:00:01",
            addr3="02:00:00:00:00:01",
        )
        / Dot11Beacon()
        / Dot11Elt(ID="SSID", info="IoT-Guard")
    )

    observation = WirelessParser().parse(frame)

    assert observation is not None
    assert observation.ssid == "IoT-Guard"
    assert observation.bssid == "02:00:00:00:00:01"
    assert observation.signal_dbm == -42
    assert PacketParser().parse(frame) is None


def test_wireless_detector_reports_deauthentication_flood_once_per_cooldown():
    now = [0.0]
    detector = WirelessAttackDetector(
        "IoT-Guard",
        "02:00:00:00:00:01",
        clock=lambda: now[0],
    )
    frame = RadioTap() / Dot11(
        type=0,
        subtype=12,
        addr1="02:00:00:00:00:02",
        addr2="02:00:00:00:00:03",
        addr3="02:00:00:00:00:01",
    ) / Dot11Deauth(reason=7)
    observation = WirelessParser().parse(frame)
    assert observation is not None

    alerts = []
    for _ in range(6):
        alerts.extend(detector.observe(observation))
        now[0] += 1

    assert [alert["attack_class"] for alert in alerts] == ["deauthentication_flood"]
    assert alerts[0]["source_mac"] == "02:00:00:00:00:03"


def test_wireless_detector_reports_evil_twin_beacon():
    detector = WirelessAttackDetector("IoT-Guard", "02:00:00:00:00:01")
    observation = WirelessObservation(
        timestamp=0,
        frame_type=0,
        frame_subtype=8,
        src_mac="02:00:00:00:00:09",
        dst_mac="ff:ff:ff:ff:ff:ff",
        bssid="02:00:00:00:00:09",
        ssid="IoT-Guard",
        signal_dbm=-30,
        channel_frequency=2437,
        protected=False,
    )

    alerts = detector.observe(observation)

    assert alerts[0]["attack_class"] == "evil_twin"