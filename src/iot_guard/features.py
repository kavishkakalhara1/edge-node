from __future__ import annotations

import math
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable


@dataclass(frozen=True)
class PacketObservation:
    timestamp: float
    src_mac: str
    dst_mac: str
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    protocol: int | None
    packet_size: int
    ip_length: int | None
    header_length: int | None
    payload_length: int | None
    ip_flags: int | None
    tcp_flags: int | None
    mss: int | None
    ttl: int | None
    window_size: int | None
    fragmented: bool


@dataclass(frozen=True)
class WindowRecord:
    device_id: str
    start: datetime
    resolution_seconds: int
    features: dict[str, float]
    packet_count: int
    byte_count: int


def _stats(values: list[float], prefix: str) -> dict[str, float]:
    if not values:
        return {
            f"{prefix}_avg": 0.0,
            f"{prefix}_max": 0.0,
            f"{prefix}_min": 0.0,
            f"{prefix}_std_deviation": 0.0,
        }
    return {
        f"{prefix}_avg": float(statistics.fmean(values)),
        f"{prefix}_max": float(max(values)),
        f"{prefix}_min": float(min(values)),
        f"{prefix}_std_deviation": float(statistics.pstdev(values)),
    }


@dataclass
class FeatureAccumulator:
    device_id: str
    device_mac: str
    start_epoch: float
    resolution_seconds: int
    packet_sizes: list[float] = field(default_factory=list)
    ip_lengths: list[float] = field(default_factory=list)
    header_lengths: list[float] = field(default_factory=list)
    payload_lengths: list[float] = field(default_factory=list)
    ip_flags: list[float] = field(default_factory=list)
    tcp_flags: list[float] = field(default_factory=list)
    mss_values: list[float] = field(default_factory=list)
    ttl_values: list[float] = field(default_factory=list)
    window_sizes: list[float] = field(default_factory=list)
    inter_arrivals: list[float] = field(default_factory=list)
    ips_all: set[str] = field(default_factory=set)
    ips_src: set[str] = field(default_factory=set)
    ips_dst: set[str] = field(default_factory=set)
    macs_all: set[str] = field(default_factory=set)
    macs_src: set[str] = field(default_factory=set)
    macs_dst: set[str] = field(default_factory=set)
    ports_all: set[int] = field(default_factory=set)
    ports_src: set[int] = field(default_factory=set)
    ports_dst: set[int] = field(default_factory=set)
    protocols_all: set[int] = field(default_factory=set)
    protocols_src: set[int] = field(default_factory=set)
    protocols_dst: set[int] = field(default_factory=set)
    packet_count: int = 0
    packets_src: int = 0
    packets_dst: int = 0
    fragmented_packets: int = 0
    byte_count: int = 0
    last_timestamp: float | None = None
    tcp_flag_counts: dict[str, int] = field(
        default_factory=lambda: {name: 0 for name in ("ack", "fin", "psh", "rst", "syn", "urg")}
    )

    def add(self, packet: PacketObservation) -> None:
        outgoing = packet.src_mac == self.device_mac
        self.packet_count += 1
        self.byte_count += packet.packet_size
        self.packets_src += int(outgoing)
        self.packets_dst += int(not outgoing)
        self.fragmented_packets += int(packet.fragmented)
        self.packet_sizes.append(float(packet.packet_size))
        self.macs_all.update((packet.src_mac, packet.dst_mac))
        self.macs_src.add(packet.src_mac)
        self.macs_dst.add(packet.dst_mac)
        if self.last_timestamp is not None:
            self.inter_arrivals.append(max(0.0, packet.timestamp - self.last_timestamp))
        self.last_timestamp = packet.timestamp
        for value, target in (
            (packet.ip_length, self.ip_lengths),
            (packet.header_length, self.header_lengths),
            (packet.payload_length, self.payload_lengths),
            (packet.ip_flags, self.ip_flags),
            (packet.tcp_flags, self.tcp_flags),
            (packet.mss, self.mss_values),
            (packet.ttl, self.ttl_values),
            (packet.window_size, self.window_sizes),
        ):
            if value is not None:
                target.append(float(value))
        if packet.src_ip:
            self.ips_all.add(packet.src_ip)
            self.ips_src.add(packet.src_ip)
        if packet.dst_ip:
            self.ips_all.add(packet.dst_ip)
            self.ips_dst.add(packet.dst_ip)
        if packet.src_port is not None:
            self.ports_all.add(packet.src_port)
            self.ports_src.add(packet.src_port)
        if packet.dst_port is not None:
            self.ports_all.add(packet.dst_port)
            self.ports_dst.add(packet.dst_port)
        if packet.protocol is not None:
            self.protocols_all.add(packet.protocol)
            (self.protocols_src if outgoing else self.protocols_dst).add(packet.protocol)
        if packet.tcp_flags is not None:
            for bit, name in ((0x10, "ack"), (0x01, "fin"), (0x08, "psh"), (0x04, "rst"), (0x02, "syn"), (0x20, "urg")):
                self.tcp_flag_counts[name] += int(bool(packet.tcp_flags & bit))

    def finish(self) -> WindowRecord:
        features: dict[str, float] = {
            "log_data-ranges_avg": 0.0,
            "log_data-ranges_max": 0.0,
            "log_data-ranges_min": 0.0,
            "log_data-ranges_std_deviation": 0.0,
            "log_data-types_count": 0.0,
            "log_interval-messages": 0.0,
            "log_messages_count": 0.0,
            "network_fragmentation-score": self.fragmented_packets / max(self.packet_count, 1),
            "network_fragmented-packets": float(self.fragmented_packets),
            "network_interval-packets": float(statistics.fmean(self.inter_arrivals)) if self.inter_arrivals else 0.0,
            "network_ips_all_count": float(len(self.ips_all)),
            "network_ips_dst_count": float(len(self.ips_dst)),
            "network_ips_src_count": float(len(self.ips_src)),
            "network_macs_all_count": float(len(self.macs_all)),
            "network_macs_dst_count": float(len(self.macs_dst)),
            "network_macs_src_count": float(len(self.macs_src)),
            "network_packets_all_count": float(self.packet_count),
            "network_packets_dst_count": float(self.packets_dst),
            "network_packets_src_count": float(self.packets_src),
            "network_ports_all_count": float(len(self.ports_all)),
            "network_ports_dst_count": float(len(self.ports_dst)),
            "network_ports_src_count": float(len(self.ports_src)),
            "network_protocols_all_count": float(len(self.protocols_all)),
            "network_protocols_dst_count": float(len(self.protocols_dst)),
            "network_protocols_src_count": float(len(self.protocols_src)),
        }
        for name, count in self.tcp_flag_counts.items():
            features[f"network_tcp-flags-{name}_count"] = float(count)
        features.update(_stats(self.header_lengths, "network_header-length"))
        features.update(_stats(self.ip_flags, "network_ip-flags"))
        features.update(_stats(self.ip_lengths, "network_ip-length"))
        features.update(_stats(self.mss_values, "network_mss"))
        features.update(_stats(self.packet_sizes, "network_packet-size"))
        features.update(_stats(self.payload_lengths, "network_payload-length"))
        features.update(_stats(self.tcp_flags, "network_tcp-flags"))
        features.update(_stats(self.inter_arrivals, "network_time-delta"))
        features.update(_stats(self.ttl_values, "network_ttl"))
        features.update(_stats(self.window_sizes, "network_window-size"))
        return WindowRecord(
            device_id=self.device_id,
            start=datetime.fromtimestamp(self.start_epoch, timezone.utc),
            resolution_seconds=self.resolution_seconds,
            features=features,
            packet_count=self.packet_count,
            byte_count=self.byte_count,
        )


class FeatureEngine:
    def __init__(self, callback: Callable[[WindowRecord], None], resolutions: tuple[int, ...] = (2, 10)):
        self.callback = callback
        self.resolutions = resolutions
        self.devices: dict[str, str] = {}
        self.accumulators: dict[tuple[str, int], FeatureAccumulator] = {}

    def register_device(self, device_id: str, device_mac: str, now: float) -> None:
        self.devices[device_id] = device_mac
        for resolution in self.resolutions:
            self._advance(device_id, resolution, now)

    def unregister_missing(self, active_ids: set[str]) -> None:
        self.devices = {key: value for key, value in self.devices.items() if key in active_ids}

    def ingest(self, device_id: str, packet: PacketObservation) -> None:
        if device_id not in self.devices:
            return
        for resolution in self.resolutions:
            accumulator = self._advance(device_id, resolution, packet.timestamp)
            accumulator.add(packet)

    def tick(self, now: float) -> None:
        for device_id in tuple(self.devices):
            for resolution in self.resolutions:
                self._advance(device_id, resolution, now)

    def _advance(self, device_id: str, resolution: int, timestamp: float) -> FeatureAccumulator:
        bucket = math.floor(timestamp / resolution) * resolution
        key = (device_id, resolution)
        current = self.accumulators.get(key)
        mac = self.devices[device_id]
        if current is None:
            current = FeatureAccumulator(device_id, mac, bucket, resolution)
            self.accumulators[key] = current
            return current
        while current.start_epoch < bucket:
            self.callback(current.finish())
            current = FeatureAccumulator(
                device_id, mac, current.start_epoch + resolution, resolution
            )
            self.accumulators[key] = current
        return current
