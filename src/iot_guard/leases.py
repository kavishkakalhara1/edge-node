from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .identity import DeviceIdentity, normalize_mac


@dataclass(frozen=True)
class Lease:
    device_id: str
    mac: str
    mac_fingerprint: str
    ipv4: str
    hostname: str | None
    expires_epoch: int


class LeaseRegistry:
    def __init__(self, path: Path, identity: DeviceIdentity):
        self.path = path
        self.identity = identity
        self.by_mac: dict[str, Lease] = {}

    def refresh(self) -> list[Lease]:
        leases: dict[str, Lease] = {}
        if not self.path.exists():
            self.by_mac = leases
            return []
        for line in self.path.read_text(errors="replace").splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            expires, raw_mac, ipv4, hostname = parts[:4]
            try:
                mac = normalize_mac(raw_mac)
                expiry = int(expires)
            except (ValueError, TypeError):
                continue
            leases[mac] = Lease(
                device_id=self.identity.device_id(mac),
                mac=mac,
                mac_fingerprint=self.identity.mac_fingerprint(mac),
                ipv4=ipv4,
                hostname=None if hostname == "*" else hostname,
                expires_epoch=expiry,
            )
        self.by_mac = leases
        return list(leases.values())

    def resolve_all(self, src_mac: str, dst_mac: str) -> tuple[Lease, ...]:
        leases = []
        for mac in (src_mac.lower(), dst_mac.lower()):
            lease = self.by_mac.get(mac)
            if lease is not None and lease not in leases:
                leases.append(lease)
        return tuple(leases)
