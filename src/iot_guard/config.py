from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .identity import normalize_mac


def _interfaces(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


def _mac_addresses(value: str) -> tuple[str, ...]:
    return tuple(normalize_mac(item) for item in value.split(",") if item.strip())


@dataclass(frozen=True)
class Settings:
    database_path: Path
    artifact_dir: Path
    dhcp_lease_file: Path
    device_registry_path: Path
    identity_secret_file: Path
    capture_interfaces: tuple[str, ...]
    ignored_device_macs: tuple[str, ...]
    protected_device_macs: tuple[str, ...]
    hotspot_interface: str
    hotspot_ssid: str
    monitor_interface: str
    hotspot_subnet: str
    web_host: str
    web_port: int
    healing_api_token: str
    cloud_api_endpoint: str
    cloud_uplink_interface: str
    cloud_api_token: str
    cloud_api_timeout_seconds: float
    cloud_anomaly_interval_seconds: float
    healing_auto_unblock_seconds: float
    healing_heartbeat_interval_seconds: float
    retention_days: int
    model_cpu_threads: int
    model_buffer_timeout_seconds: float
    model_log_latency: bool
    model_allow_fallback: bool
    model_max_latency_ms: float

    @classmethod
    def from_env(cls) -> "Settings":
        state_dir = Path(os.getenv("IOT_GUARD_STATE_DIR", "/var/lib/iot-guard"))
        settings = cls(
            database_path=Path(os.getenv("IOT_GUARD_DATABASE", state_dir / "iot-guard.db")),
            artifact_dir=Path(os.getenv("IOT_GUARD_ARTIFACT_DIR", "/opt/iot-guard/model")),
            dhcp_lease_file=Path(
                os.getenv("IOT_GUARD_DHCP_LEASE_FILE", "/var/lib/NetworkManager/dnsmasq-wlan0.leases")
            ),
            device_registry_path=Path(
                os.getenv("IOT_GUARD_DEVICE_REGISTRY", "/etc/iot-guard/devices.json")
            ),
            identity_secret_file=Path(
                os.getenv("IOT_GUARD_ID_SECRET_FILE", "/etc/iot-guard/device-id.key")
            ),
            capture_interfaces=_interfaces(
                os.getenv("IOT_GUARD_CAPTURE_INTERFACES", "wlan0")
            ),
            ignored_device_macs=_mac_addresses(
                os.getenv("IOT_GUARD_IGNORED_DEVICE_MACS", "")
            ),
            protected_device_macs=_mac_addresses(
                os.getenv("IOT_GUARD_PROTECTED_DEVICE_MACS", "")
            ),
            hotspot_interface=os.getenv("IOT_GUARD_HOTSPOT_INTERFACE", "wlan0"),
            hotspot_ssid=os.getenv("IOT_GUARD_HOTSPOT_SSID", "IoT-Guard"),
            monitor_interface=os.getenv("IOT_GUARD_MONITOR_INTERFACE", ""),
            hotspot_subnet=os.getenv("IOT_GUARD_HOTSPOT_SUBNET", "10.42.0.0/24"),
            web_host=os.getenv("IOT_GUARD_WEB_HOST", "0.0.0.0"),
            web_port=int(os.getenv("IOT_GUARD_WEB_PORT", "8080")),
            healing_api_token=os.getenv("IOT_GUARD_HEALING_API_TOKEN", ""),
            cloud_api_endpoint=os.getenv("IOT_GUARD_CLOUD_API_ENDPOINT", ""),
            cloud_uplink_interface=os.getenv("IOT_GUARD_CLOUD_UPLINK_INTERFACE", "eth0"),
            cloud_api_token=os.getenv("IOT_GUARD_CLOUD_API_TOKEN", ""),
            cloud_api_timeout_seconds=float(
                os.getenv("IOT_GUARD_CLOUD_API_TIMEOUT_SECONDS", "30")
            ),
            cloud_anomaly_interval_seconds=float(
                os.getenv("IOT_GUARD_CLOUD_ANOMALY_INTERVAL_SECONDS", "120")
            ),
            healing_auto_unblock_seconds=float(
                os.getenv("IOT_GUARD_HEALING_AUTO_UNBLOCK_SECONDS", "60")
            ),
            healing_heartbeat_interval_seconds=float(
                os.getenv("IOT_GUARD_HEALING_HEARTBEAT_INTERVAL_SECONDS", "30")
            ),
            retention_days=int(os.getenv("IOT_GUARD_RETENTION_DAYS", "30")),
            model_cpu_threads=int(os.getenv("IOT_GUARD_MODEL_CPU_THREADS", "2")),
            model_buffer_timeout_seconds=float(
                os.getenv("IOT_GUARD_MODEL_BUFFER_TIMEOUT_SECONDS", "120")
            ),
            model_log_latency=os.getenv("IOT_GUARD_MODEL_LOG_LATENCY", "false").lower()
            in {"1", "true", "yes"},
            model_allow_fallback=os.getenv("IOT_GUARD_MODEL_ALLOW_FALLBACK", "false").lower()
            in {"1", "true", "yes"},
            model_max_latency_ms=float(os.getenv("IOT_GUARD_MODEL_MAX_LATENCY_MS", "0")),
        )
        if (
            settings.cloud_api_endpoint
            and settings.cloud_uplink_interface == settings.hotspot_interface
        ):
            raise ValueError("Cloud uplink and IoT hotspot must use different interfaces")
        if (
            settings.monitor_interface
            and settings.monitor_interface == settings.hotspot_interface
        ):
            raise ValueError("IoT hotspot and monitor must use different interfaces")
        return settings
