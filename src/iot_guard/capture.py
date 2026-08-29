from __future__ import annotations

import logging
import time
from collections import OrderedDict
from typing import Callable

from .features import PacketObservation
from .identity import normalize_mac
from .leases import LeaseRegistry

LOGGER = logging.getLogger(__name__)


class PacketParser:
    def parse(self, packet) -> PacketObservation | None:
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.l2 import Ether

        if not packet.haslayer(Ether):
            try:
                packet = Ether(bytes(packet))
            except (TypeError, ValueError):
                return None
        if not packet.haslayer(IP):
            return None
        ethernet = packet[Ether]
        ip = packet[IP]
        try:
            src_mac = normalize_mac(ethernet.src)
            dst_mac = normalize_mac(ethernet.dst)
        except ValueError:
            return None
        transport = packet[TCP] if packet.haslayer(TCP) else packet[UDP] if packet.haslayer(UDP) else None
        tcp = packet[TCP] if packet.haslayer(TCP) else None
        mss = None
        if tcp is not None:
            for option, value in tcp.options:
                if option == "MSS":
                    mss = int(value)
                    break
        fragment_offset = int(ip.frag)
        more_fragments = bool(int(ip.flags) & 0x1)
        return PacketObservation(
            timestamp=float(getattr(packet, "time", time.time())),
            src_mac=src_mac,
            dst_mac=dst_mac,
            src_ip=str(ip.src),
            dst_ip=str(ip.dst),
            src_port=int(transport.sport) if transport is not None else None,
            dst_port=int(transport.dport) if transport is not None else None,
            protocol=int(ip.proto),
            packet_size=len(packet),
            ip_length=int(ip.len or len(ip)),
            header_length=int(ip.ihl or 5) * 4,
            payload_length=len(bytes(ip.payload)),
            ip_flags=int(ip.flags),
            tcp_flags=int(tcp.flags) if tcp is not None else None,
            mss=mss,
            ttl=int(ip.ttl),
            window_size=int(tcp.window) if tcp is not None else None,
            fragmented=fragment_offset > 0 or more_fragments,
        )


class DuplicateFilter:
    def __init__(self, max_entries: int = 20_000, ttl_seconds: float = 0.5):
        self.max_entries = max_entries
        self.ttl_seconds = ttl_seconds
        self.seen: OrderedDict[tuple, float] = OrderedDict()

    def accepts(self, packet: PacketObservation) -> bool:
        key = (
            round(packet.timestamp, 3), packet.src_mac, packet.dst_mac,
            packet.src_ip, packet.dst_ip, packet.src_port, packet.dst_port,
            packet.protocol, packet.packet_size,
        )
        now = time.monotonic()
        previous = self.seen.get(key)
        self.seen[key] = now
        self.seen.move_to_end(key)
        while self.seen and (
            len(self.seen) > self.max_entries
            or now - next(iter(self.seen.values())) > self.ttl_seconds
        ):
            self.seen.popitem(last=False)
        return previous is None or now - previous > self.ttl_seconds


class CaptureService:
    def __init__(
        self,
        interfaces: tuple[str, ...],
        leases: LeaseRegistry,
        callback: Callable[[str, PacketObservation], None],
    ):
        self.interfaces = interfaces
        self.leases = leases
        self.callback = callback
        self.parser = PacketParser()
        self.duplicates = DuplicateFilter()
        self.sniffers = []

    def start(self) -> None:
        from scapy.sendrecv import AsyncSniffer

        for interface in self.interfaces:
            sniffer = AsyncSniffer(
                iface=interface,
                promisc=False,
                store=False,
                prn=lambda packet, source=interface: self._handle(source, packet),
            )
            sniffer.start()
            self.sniffers.append(sniffer)
            LOGGER.info("Passive capture started on %s", interface)

    def stop(self) -> None:
        for sniffer in self.sniffers:
            if sniffer.running:
                sniffer.stop()
        self.sniffers.clear()

    def _handle(self, interface: str, packet) -> None:
        try:
            observation = self.parser.parse(packet)
            if observation is None or not self.duplicates.accepts(observation):
                return
            for lease in self.leases.resolve_all(observation.src_mac, observation.dst_mac):
                self.callback(lease.device_id, observation)
        except Exception:
            LOGGER.exception("Packet processing failed on %s", interface)
