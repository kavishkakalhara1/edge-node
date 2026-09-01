import threading
import time
from dataclasses import replace

from iot_guard.features import FeatureAccumulator, FeatureEngine, PacketObservation


MODEL_FEATURES = {
    "log_data-ranges_avg", "log_data-ranges_std_deviation", "log_data-types",
    "log_interval-messages", "log_messages_count", "network_header-length_avg",
    "network_header-length_std_deviation", "network_interval-packets",
    "network_ip-flags_avg", "network_ip-flags_min", "network_ip-length_avg",
    "network_ip-length_max", "network_ip-length_min", "network_ips_all",
    "network_ips_all_count", "network_ips_dst", "network_macs_all", "network_mss_avg",
    "network_mss_std_deviation", "network_packet-size_avg", "network_packet-size_min",
    "network_packets_all_count", "network_ports_all", "network_ports_all_count",
    "network_protocols_all", "network_protocols_all_count", "network_protocols_dst",
    "network_protocols_src", "network_tcp-flags-fin_count",
    "network_tcp-flags-rst_count", "network_tcp-flags-syn_count",
    "network_time-delta_avg", "network_time-delta_max", "network_time-delta_min",
    "network_time-delta_std_deviation", "network_ttl_avg",
}


def packet(timestamp: float = 1.0) -> PacketObservation:
    return PacketObservation(
        timestamp=timestamp,
        src_mac="02:00:00:00:00:01",
        dst_mac="02:00:00:00:00:02",
        src_ip="10.42.0.2",
        dst_ip="1.1.1.1",
        src_port=50000,
        dst_port=443,
        protocol=6,
        packet_size=100,
        ip_length=86,
        header_length=20,
        payload_length=66,
        ip_flags=2,
        tcp_flags=0x12,
        mss=1460,
        ttl=64,
        window_size=64240,
        fragmented=False,
    )


def test_feature_accumulator_tracks_direction_and_statistics():
    accumulator = FeatureAccumulator("iot-test", "02:00:00:00:00:01", 0, 2)
    accumulator.add(packet(1.0))
    accumulator.add(packet(1.5))
    result = accumulator.finish()
    assert result.packet_count == 2
    assert result.byte_count == 200
    assert result.features["network_packets_src_count"] == 2
    assert result.features["network_packet-size_avg"] == 100
    assert result.features["network_tcp-flags-syn_count"] == 2
    assert result.features["network_time-delta_avg"] == 0.5
    assert MODEL_FEATURES <= result.features.keys()


def test_feature_window_retains_dominant_incoming_peer():
    accumulator = FeatureAccumulator("victim", "02:00:00:00:00:02", 0, 2)
    accumulator.add(packet(1.0))
    accumulator.add(packet(1.5))

    result = accumulator.finish()

    assert result.top_incoming_peer_mac == "02:00:00:00:00:01"
    assert result.top_incoming_peer_ip == "10.42.0.2"
    assert result.top_outgoing_peer_mac is None


def test_feature_accumulator_tracks_both_ap_traffic_directions():
    device_mac = "02:00:00:00:00:01"
    peer_mac = "02:00:00:00:00:02"
    accumulator = FeatureAccumulator("iot-test", device_mac, 0, 2)
    outgoing = packet(1.0)
    incoming = replace(
        outgoing,
        timestamp=1.5,
        src_mac=peer_mac,
        dst_mac=device_mac,
        src_ip="1.1.1.1",
        dst_ip="10.42.0.2",
        src_port=443,
        dst_port=50000,
    )

    accumulator.add(outgoing)
    accumulator.add(incoming)
    result = accumulator.finish()

    assert result.features["network_packets_src_count"] == 1
    assert result.features["network_packets_dst_count"] == 1
    assert result.top_outgoing_peer_mac == peer_mac
    assert result.top_incoming_peer_mac == peer_mac


def test_feature_engine_serializes_concurrent_window_advances():
    completed = []

    def finish(record):
        time.sleep(0.02)
        completed.append(record)

    engine = FeatureEngine(finish, resolutions=(2,))
    engine.register_device("iot-test", "02:00:00:00:00:01", 0)
    engine.ingest("iot-test", packet(1.0))
    barrier = threading.Barrier(3)

    def advance():
        barrier.wait()
        engine.tick(2.0)

    threads = [threading.Thread(target=advance) for _ in range(2)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join()

    assert len(completed) == 1
    assert completed[0].packet_count == 1
