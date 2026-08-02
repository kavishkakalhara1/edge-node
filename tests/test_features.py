from iot_guard.features import FeatureAccumulator, PacketObservation


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
