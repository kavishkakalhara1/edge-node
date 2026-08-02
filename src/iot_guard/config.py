from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _interfaces(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


@dataclass(frozen=True)
class Settings:
    database_path: Path
    artifact_dir: Path
    dhcp_lease_file: Path
    identity_secret_file: Path
    capture_interfaces: tuple[str, ...]
    hotspot_interface: str
    monitor_interface: str
    hotspot_subnet: str
    web_host: str
    web_port: int
    retention_days: int
    risk_half_life_hours: float

    @classmethod
    def from_env(cls) -> "Settings":
        state_dir = Path(os.getenv("IOT_GUARD_STATE_DIR", "/var/lib/iot-guard"))
        return cls(
            database_path=Path(os.getenv("IOT_GUARD_DATABASE", state_dir / "iot-guard.db")),
            artifact_dir=Path(os.getenv("IOT_GUARD_ARTIFACT_DIR", "/opt/iot-guard/model")),
            dhcp_lease_file=Path(
                os.getenv("IOT_GUARD_DHCP_LEASE_FILE", "/var/lib/NetworkManager/dnsmasq-wlan0.leases")
            ),
            identity_secret_file=Path(
                os.getenv("IOT_GUARD_ID_SECRET_FILE", "/etc/iot-guard/device-id.key")
            ),
            capture_interfaces=_interfaces(
                os.getenv("IOT_GUARD_CAPTURE_INTERFACES", "wlan0,wlan1mon")
            ),
            hotspot_interface=os.getenv("IOT_GUARD_HOTSPOT_INTERFACE", "wlan0"),
            monitor_interface=os.getenv("IOT_GUARD_MONITOR_INTERFACE", "wlan1mon"),
            hotspot_subnet=os.getenv("IOT_GUARD_HOTSPOT_SUBNET", "10.42.0.0/24"),
            web_host=os.getenv("IOT_GUARD_WEB_HOST", "0.0.0.0"),
            web_port=int(os.getenv("IOT_GUARD_WEB_PORT", "8080")),
            retention_days=int(os.getenv("IOT_GUARD_RETENTION_DAYS", "30")),
            risk_half_life_hours=float(os.getenv("IOT_GUARD_RISK_HALF_LIFE_HOURS", "6")),
        )
