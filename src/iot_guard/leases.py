from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .identity import DeviceIdentity, normalize_mac

LOGGER = logging.getLogger(__name__)


class DeviceNameRegistry:
    def __init__(self, path: Path | None = None):
        self.path = path
        self.names: dict[str, str] = {}

    def refresh(self) -> None:
        self.names = {}
        if self.path is None:
            return
        try:
            document = json.loads(self.path.read_text())
        except FileNotFoundError:
            return
        except (OSError, json.JSONDecodeError) as exc:
            LOGGER.warning("Unable to read device registry %s: %s", self.path, exc)
            return
        records = document.get("devices") if isinstance(document, dict) else None
        if not isinstance(records, list):
            LOGGER.warning("Device registry %s must contain a devices list", self.path)
            return
        for index, record in enumerate(records):
            if not isinstance(record, dict):
                LOGGER.warning("Ignoring invalid device registry entry %s", index)
                continue
            try:
                mac = normalize_mac(record.get("mac_address"))
            except (TypeError, ValueError):
                LOGGER.warning("Ignoring device registry entry %s with invalid MAC", index)
                continue
            name = record.get("name")
            if not isinstance(name, str) or not name.strip():
                LOGGER.warning("Ignoring device registry entry %s with invalid name", index)
                continue
            if mac in self.names:
                LOGGER.warning("Ignoring duplicate device registry MAC %s", mac)
                continue
            self.names[mac] = name.strip()

    def name_for(self, mac: str) -> str | None:
        return self.names.get(normalize_mac(mac))


def parse_station_macs(output: str) -> set[str]:
    macs = set()
    for line in output.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and parts[0] == "Station":
            try:
                macs.add(normalize_mac(parts[1]))
            except ValueError:
                continue
    return macs


def associated_macs(interface: str) -> set[str] | None:
    try:
        result = subprocess.run(
            ["iw", "dev", interface, "station", "dump"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return parse_station_macs(result.stdout)


@dataclass(frozen=True)
class Lease:
    device_id: str
    mac: str
    mac_fingerprint: str
    ipv4: str
    hostname: str | None
    expires_epoch: int


class LeaseRegistry:
    def __init__(
        self,
        path: Path,
        identity: DeviceIdentity,
        device_registry_path: Path | None = None,
    ):
        self.path = path
        self.identity = identity
        self.device_names = DeviceNameRegistry(device_registry_path)
        self.by_mac: dict[str, Lease] = {}
        self.by_ipv4: dict[str, Lease] = {}

    def refresh(self) -> list[Lease]:
        self.device_names.refresh()
        leases: dict[str, Lease] = {}
        try:
            lines = self.path.read_text(errors="replace").splitlines()
        except (FileNotFoundError, PermissionError):
            self.by_mac = leases
            self.by_ipv4 = {}
            return []
        for line in lines:
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
                hostname=self.device_names.name_for(mac)
                or (None if hostname == "*" else hostname),
                expires_epoch=expiry,
            )
        self.by_mac = leases
        self.by_ipv4 = {lease.ipv4: lease for lease in leases.values()}
        return list(leases.values())

    def configured_name(self, mac: str) -> str | None:
        return self.device_names.name_for(mac)

    def resolve_all(
        self,
        src_mac: str,
        dst_mac: str,
        src_ip: str | None = None,
        dst_ip: str | None = None,
    ) -> tuple[Lease, ...]:
        leases = []
        for mac in (src_mac.lower(), dst_mac.lower()):
            lease = self.by_mac.get(mac)
            if lease is not None and lease not in leases:
                leases.append(lease)
        for ipv4 in (src_ip, dst_ip):
            lease = self.by_ipv4.get(ipv4) if ipv4 is not None else None
            if lease is not None and lease not in leases:
                leases.append(lease)
        return tuple(leases)
