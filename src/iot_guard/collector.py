from __future__ import annotations

import logging
import os
import signal
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .capture import CaptureService, WirelessObservation
from .cloud import CloudReporter
from .config import Settings
from .database import Database
from .features import FeatureEngine, PacketObservation, WindowRecord
from .healing import CLOUD_ACTIONS, HealingWorker, NftablesHealingExecutor
from .identity import DeviceIdentity, normalize_mac
from .leases import LeaseRegistry, associated_macs
from .model import ProductionEnsemble
from .risk import update_risk
from .wireless import WirelessAttackDetector

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class BufferedRecord:
    timestamp: float
    features: dict[str, float]


class RollingWindowBuffer:
    def __init__(self, window_size: int, stale_timeout_seconds: float):
        self.window_size = window_size
        self.stale_timeout_seconds = stale_timeout_seconds
        self.buffers: dict[tuple[str, int, str], deque[BufferedRecord]] = {}

    def add(
        self,
        device_id: str,
        resolution_seconds: int,
        session_id: str,
        timestamp: float,
        features: dict[str, float],
    ) -> list[dict[str, float]] | None:
        key = (device_id, resolution_seconds, session_id)
        buffer = self.buffers.setdefault(key, deque(maxlen=self.window_size))
        if buffer:
            gap = timestamp - buffer[-1].timestamp
            if gap <= 0 or gap > resolution_seconds * 1.5:
                buffer.clear()
        buffer.append(BufferedRecord(timestamp, features))
        if len(buffer) < self.window_size:
            return None
        return [record.features for record in buffer]

    def clear_stale(self, now: float) -> None:
        stale_keys = [
            key
            for key, buffer in self.buffers.items()
            if not buffer or now - buffer[-1].timestamp > self.stale_timeout_seconds
        ]
        for key in stale_keys:
            del self.buffers[key]

    def clear_device(self, device_id: str) -> None:
        for key in [key for key in self.buffers if key[0] == device_id]:
            del self.buffers[key]


class Collector:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.database = Database(settings.database_path)
        self.identity = DeviceIdentity.from_file(settings.identity_secret_file)
        self.leases = LeaseRegistry(
            settings.dhcp_lease_file,
            self.identity,
            settings.device_registry_path,
        )
        self.model = ProductionEnsemble(
            settings.artifact_dir,
            cpu_threads=settings.model_cpu_threads,
            allow_fallback=settings.model_allow_fallback,
        )
        self.session_id = uuid.uuid4().hex
        self.windows = RollingWindowBuffer(
            self.model.window_size, settings.model_buffer_timeout_seconds
        )
        self.features = FeatureEngine(self._window_ready)
        self.capture = CaptureService(
            settings.capture_interfaces,
            self.leases,
            self._packet_ready,
            self._wireless_ready,
        )
        self.wireless = WirelessAttackDetector(
            settings.hotspot_ssid,
            self._interface_mac(settings.hotspot_interface),
        )
        self.healing = HealingWorker(
            self.database,
            NftablesHealingExecutor(
                hotspot_interface=settings.hotspot_interface,
                protected_macs=settings.protected_device_macs,
            ),
            completion_listener=self._on_healing_completed,
        )
        self.cloud = CloudReporter(
            settings.cloud_api_endpoint,
            settings.cloud_uplink_interface,
            token=settings.cloud_api_token,
            timeout_seconds=settings.cloud_api_timeout_seconds,
            recorder=self.database.record_cloud_delivery,
        )
        self.next_anomaly_report_at: dict[str, float] = {}
        self.anomaly_report_interval_seconds = settings.cloud_anomaly_interval_seconds
        self.active_healings: dict[str, dict] = {}
        self.healing_auto_unblock_seconds = settings.healing_auto_unblock_seconds
        self.healing_heartbeat_interval_seconds = settings.healing_heartbeat_interval_seconds
        self.stop_event = threading.Event()
        self.last_cleanup = 0.0
        self.risk_date = datetime.now(timezone.utc).date()

    def start(self) -> None:
        self.database.initialize()
        self.database.reset_daily_risk()
        self.healing.prepare()
        if not self.settings.dhcp_lease_file.is_file():
            LOGGER.error(
                "DHCP lease file does not exist: %s; connected devices cannot be discovered",
                self.settings.dhcp_lease_file,
            )
        elif not os.access(self.settings.dhcp_lease_file, os.R_OK):
            LOGGER.error(
                "DHCP lease file is not readable: %s; connected devices cannot be discovered",
                self.settings.dhcp_lease_file,
            )
        self.refresh_devices()
        self.capture.start()
        LOGGER.info("Collector started with model artifact %s", self.model.metadata["artifact_version"])
        try:
            while not self.stop_event.wait(1.0):
                now = time.time()
                current_date = datetime.now(timezone.utc).date()
                if current_date != self.risk_date:
                    self.database.reset_daily_risk()
                    self.risk_date = current_date
                self.refresh_devices()
                self.features.tick(now)
                self.windows.clear_stale(now)
                for _ in range(10):
                    if not self.healing.process_one():
                        break
                self._maintain_healings()
                if now - self.last_cleanup >= 3600:
                    self.database.cleanup(self.settings.retention_days)
                    self.last_cleanup = now
        finally:
            self.capture.stop()
            self.cloud.close()
            LOGGER.info("Collector stopped")

    def stop(self, *_args) -> None:
        self.stop_event.set()

    def refresh_devices(self) -> None:
        leases = self.leases.refresh()
        lease_by_mac = {lease.mac: lease for lease in leases}
        stations = associated_macs(self.settings.hotspot_interface)
        if stations is None:
            LOGGER.warning(
                "Unable to read associated stations from %s; preserving device state",
                self.settings.hotspot_interface,
            )
            return
        active_macs = stations - set(self.settings.ignored_device_macs)
        now = time.time()
        active_ids = set()
        for lease in leases:
            if lease.mac not in active_macs:
                continue
            self.database.upsert_device(
                lease.device_id,
                lease.mac_fingerprint,
                lease.hostname,
                lease.ipv4,
                mac_address=lease.mac,
            )
            active_ids.add(lease.device_id)
            self.features.register_device(lease.device_id, lease.mac, now)
        for mac in active_macs - set(lease_by_mac):
            device_id = self.identity.device_id(mac)
            active_ids.add(device_id)
            self.database.upsert_device(
                device_id,
                self.identity.mac_fingerprint(mac),
                self.leases.configured_name(mac),
                None,
                mac_address=mac,
            )
            self.features.register_device(device_id, mac, now)
        disconnected = set(self.features.devices) - active_ids
        self.features.unregister_missing(active_ids)
        for device_id in disconnected:
            self.windows.clear_device(device_id)
        self.database.mark_disconnected_except(active_ids)

    def _packet_ready(self, device_id: str, packet: PacketObservation) -> None:
        self.features.ingest(device_id, packet)

    def _wireless_ready(self, observation: WirelessObservation) -> None:
        for alert in self.wireless.observe(observation):
            self.database.log(
                "warning",
                "wireless",
                f"Wireless attack detected: {alert['attack_class']}",
                alert,
            )
            LOGGER.warning(
                "Wireless attack class=%s source=%s target=%s",
                alert["attack_class"],
                alert["source_mac"],
                alert["target_mac"],
            )

    @staticmethod
    def _interface_mac(interface: str) -> str | None:
        try:
            value = Path(f"/sys/class/net/{interface}/address").read_text().strip()
            return normalize_mac(value)
        except (FileNotFoundError, OSError, ValueError):
            return None

    def _ratios(self, result: dict) -> dict:
        enriched = {
            **result,
            "point_ratio": float(result.get("point_score") or 0.0)
            / max(float(self.model.metadata["point_threshold"]), 1e-9),
            "temporal_ratio": float(result.get("temporal_score") or 0.0)
            / max(float(self.model.metadata["temporal_threshold"]), 1e-9),
            "fused_ratio": float(result.get("ensemble_score") or 0.0)
            / max(float(self.model.metadata["ensemble_threshold"]), 1e-9),
        }
        evidence_ratio = max(
            enriched["point_ratio"], enriched["temporal_ratio"], enriched["fused_ratio"]
        )
        normalized_evidence = evidence_ratio / (1.0 + evidence_ratio)
        enriched["gru_score"] = normalized_evidence
        enriched["svdd_score"] = normalized_evidence
        return enriched

    def _store_result(
        self,
        device_id: str,
        observed_at: str,
        result: dict,
        network_features: dict[str, float],
        attack_context: dict | None = None,
    ) -> None:
        enriched = self._ratios(result)
        if attack_context is not None:
            enriched["attack_context"] = attack_context
        current, updated_at, consecutive_anomalies = self.database.device_risk(device_id)
        risk = update_risk(
            current,
            updated_at,
            enriched,
            consecutive_anomalies=consecutive_anomalies,
        )
        self.database.record_inference(device_id, observed_at, enriched, risk)
        if enriched.get("is_anomaly"):
            now = time.monotonic()
            if now >= self.next_anomaly_report_at.get(device_id, 0.0):
                payload = {
                    "flag": "anomaly",
                    "risk_score": risk.current,
                    "network_features": dict(network_features),
                    "device_id": device_id,
                }
                if attack_context is not None:
                    payload["attack_context"] = attack_context
                response = self.cloud.submit(payload)
                self.next_anomaly_report_at[device_id] = (
                    time.monotonic() + self.anomaly_report_interval_seconds
                )
                if response is not False:
                    self._queue_cloud_actions(response, observed_at, attack_context)
            LOGGER.warning(
                "Anomaly device=%s type=%s risk=%.1f",
                device_id,
                enriched.get("anomaly_type"),
                risk.current,
            )

    def _queue_cloud_actions(
        self,
        response: object,
        observed_at: str,
        attack_context: dict | None = None,
    ) -> None:
        if not isinstance(response, dict):
            return
        actions = response.get("actions", [])
        if not isinstance(actions, list):
            LOGGER.error("Cloud response actions must be a list")
            return
        for index, action in enumerate(actions):
            if not isinstance(action, dict):
                LOGGER.error("Ignoring malformed cloud healing action: %r", action)
                continue
            action_id = str(action.get("action_id", "")).upper()
            device_id = action.get("device_id")
            target_role = action.get("target")
            if target_role in {"attacker", "victim"} and attack_context is not None:
                target = attack_context.get(target_role)
                if isinstance(target, dict):
                    device_id = target.get("device_id")
            parameters = action.get("parameters", {})
            if action_id not in CLOUD_ACTIONS or not isinstance(device_id, str):
                LOGGER.error(
                    "Ignoring unsupported cloud healing action action=%s device=%r",
                    action_id,
                    device_id,
                )
                continue
            if self._protected_target(device_id, attack_context):
                LOGGER.error(
                    "Ignoring healing action targeting protected device action=%s device=%s",
                    action_id,
                    device_id,
                )
                continue
            if not isinstance(parameters, dict):
                LOGGER.error("Ignoring cloud healing action with invalid parameters: %r", action)
                continue
            parameters = dict(parameters)
            for key in (
                "attacker_ip",
                "attacker_ipv4",
                "source_ipv4",
                "source_cidr",
                "destination_ipv4",
            ):
                if key in action and key not in parameters:
                    parameters[key] = action[key]
            if attack_context is not None:
                attacker = attack_context.get("attacker")
                victim = attack_context.get("victim")
                if isinstance(attacker, dict):
                    parameters.setdefault("attacker_device_id", attacker.get("device_id"))
                    parameters.setdefault("attacker_mac", attacker.get("mac_address"))
                    parameters.setdefault("attacker_ip", attacker.get("ipv4"))
                    if action_id == "NET-03" and attacker.get("ipv4"):
                        parameters.setdefault("source_ipv4", attacker["ipv4"])
                if isinstance(victim, dict):
                    parameters.setdefault("victim_device_id", victim.get("device_id"))
            request_id = uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"iot-guard:{observed_at}:{index}:{action_id}:{device_id}",
            ).hex
            queued = self.database.create_healing_request(
                request_id,
                action_id,
                device_id,
                parameters,
                source="cloud",
            )
            if queued is None:
                LOGGER.error(
                    "Cloud healing action references unknown device action=%s device=%s",
                    action_id,
                    device_id,
                )
                continue
            LOGGER.info(
                "Cloud healing action queued request=%s action=%s device=%s",
                request_id,
                action_id,
                device_id,
            )

    def _protected_target(self, device_id: str, attack_context: dict | None) -> bool:
        settings = getattr(self, "settings", None)
        protected_macs = set(getattr(settings, "protected_device_macs", ()))
        if not protected_macs:
            return False
        if attack_context is not None:
            for role in ("attacker", "victim"):
                details = attack_context.get(role)
                if (
                    isinstance(details, dict)
                    and details.get("device_id") == device_id
                    and details.get("mac_address") in protected_macs
                ):
                    return True
        identity = getattr(self, "identity", None)
        return identity is not None and device_id in {
            identity.device_id(mac) for mac in protected_macs
        }

    def _on_healing_completed(
        self,
        request: dict,
        result: dict | None,
        error: str | None,
    ) -> None:
        device_id = request.get("device_id")
        action_id = request.get("action_id")
        if not isinstance(device_id, str) or not isinstance(action_id, str):
            return
        if error is not None:
            return
        if action_id == "UNBLOCK":
            active = self.active_healings.pop(device_id, None)
            self.next_anomaly_report_at.pop(device_id, None)
            self.cloud.submit(
                {
                    "flag": "healing_expired",
                    "device_id": device_id,
                    "action_id": (active or {}).get("action_id"),
                    "trigger": request.get("source", "manual"),
                    "result": result,
                }
            )
            return
        action = CLOUD_ACTIONS.get(action_id)
        if action is None or not action.reversible:
            return
        now = time.monotonic()
        self.active_healings[device_id] = {
            "action_id": action_id,
            "device_id": device_id,
            "ipv4": request.get("ipv4"),
            "mac_address": request.get("mac_address"),
            "parameters": request.get("parameters", {}),
            "source": request.get("source", "dashboard"),
            "started_at": now,
            "unblock_at": now + self.healing_auto_unblock_seconds,
            "next_heartbeat_at": now + self.healing_heartbeat_interval_seconds,
            "unblock_queued": False,
        }
        self.next_anomaly_report_at.pop(device_id, None)
        self.cloud.submit(
            {
                "flag": "healing_active",
                "device_id": device_id,
                "action_id": action_id,
                "action_name": action.name,
                "auto_unblock_in_seconds": self.healing_auto_unblock_seconds,
                "source": request.get("source", "dashboard"),
                "result": result,
            }
        )

    def _maintain_healings(self) -> None:
        if not self.active_healings:
            return
        now = time.monotonic()
        for device_id, entry in list(self.active_healings.items()):
            if not entry["unblock_queued"] and now >= entry["unblock_at"]:
                request_id = uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    f"iot-guard:auto-unblock:{entry['started_at']}:{device_id}",
                ).hex
                queued = self.database.create_healing_request(
                    request_id,
                    "UNBLOCK",
                    device_id,
                    {
                        "reason": "auto_expire",
                        "original_action_id": entry["action_id"],
                    },
                    source="auto",
                )
                if queued is None:
                    LOGGER.warning(
                        "Auto-unblock skipped; device gone device=%s action=%s",
                        device_id,
                        entry["action_id"],
                    )
                    self.active_healings.pop(device_id, None)
                    continue
                entry["unblock_queued"] = True
                LOGGER.info(
                    "Auto-unblock queued device=%s action=%s after=%.0fs",
                    device_id,
                    entry["action_id"],
                    self.healing_auto_unblock_seconds,
                )
                continue
            if now >= entry["next_heartbeat_at"]:
                elapsed = now - entry["started_at"]
                remaining = max(0.0, entry["unblock_at"] - now)
                self.cloud.submit(
                    {
                        "flag": "healing_heartbeat",
                        "device_id": device_id,
                        "action_id": entry["action_id"],
                        "elapsed_seconds": round(elapsed, 3),
                        "remaining_seconds": round(remaining, 3),
                    }
                )
                entry["next_heartbeat_at"] = (
                    now + self.healing_heartbeat_interval_seconds
                )

    def _attack_context(self, window: WindowRecord) -> dict | None:
        devices_by_mac = {
            mac: device_id for device_id, mac in self.features.devices.items()
        }
        protected_macs = set(self.settings.protected_device_macs)

        def details(mac_address: str | None, ipv4: str | None) -> dict | None:
            if mac_address is None or mac_address in protected_macs:
                return None
            device_id = devices_by_mac.get(mac_address)
            if device_id is None:
                return None
            lease = self.leases.by_mac.get(mac_address)
            return {
                "device_id": device_id,
                "mac_address": mac_address,
                "ipv4": lease.ipv4 if lease is not None else ipv4,
                "hostname": lease.hostname if lease is not None else None,
            }

        current_mac = self.features.devices.get(window.device_id)
        current = details(current_mac, None)
        incoming = details(window.top_incoming_peer_mac, window.top_incoming_peer_ip)
        outgoing = details(window.top_outgoing_peer_mac, window.top_outgoing_peer_ip)
        incoming_count = window.features.get("network_packets_dst_count", 0.0)
        outgoing_count = window.features.get("network_packets_src_count", 0.0)
        if current is None:
            return None
        if incoming is not None and incoming_count >= outgoing_count:
            return {"basis": "dominant_incoming_peer", "attacker": incoming, "victim": current}
        if outgoing is not None:
            return {"basis": "dominant_outgoing_peer", "attacker": current, "victim": outgoing}
        return None

    def _window_ready(self, window: WindowRecord) -> None:
        observed_at = window.start.astimezone(timezone.utc).isoformat()
        self.database.record_window(
            window.device_id,
            observed_at,
            window.resolution_seconds,
            window.packet_count,
            window.byte_count,
            window.features,
        )
        records = self.windows.add(
            window.device_id,
            window.resolution_seconds,
            self.session_id,
            window.start.timestamp(),
            window.features,
        )
        if records is None:
            return
        started = time.perf_counter()
        score = self.model.score_window(records)
        elapsed_ms = (time.perf_counter() - started) * 1000
        if self.settings.model_log_latency:
            LOGGER.info(
                "Inference device=%s interval=%ss latency_ms=%.3f fallback=%s",
                window.device_id,
                window.resolution_seconds,
                elapsed_ms,
                score["fallback"],
            )
        if (
            self.settings.model_max_latency_ms > 0
            and elapsed_ms > self.settings.model_max_latency_ms
            and self.settings.model_allow_fallback
            and not self.model.is_fallback
        ):
            LOGGER.warning(
                "Inference latency %.3fms exceeds %.3fms; activating fallback",
                elapsed_ms,
                self.settings.model_max_latency_ms,
            )
            self.model.activate_fallback("inference latency limit exceeded")
            self.windows = RollingWindowBuffer(
                self.model.window_size, self.settings.model_buffer_timeout_seconds
            )
        is_point = window.resolution_seconds == 2
        result = {
            "point_score": score["raw_score"] if is_point else None,
            "point_anomaly": score["is_anomaly"] if is_point else False,
            "temporal_score": None if is_point else score["raw_score"],
            "temporal_anomaly": False if is_point else score["is_anomaly"],
            "ensemble_score": score["raw_score"],
            "fused_score_anomaly": score["is_anomaly"],
            "is_anomaly": score["is_anomaly"],
            "anomaly_type": (
                "point" if is_point and score["is_anomaly"]
                else "temporal" if score["is_anomaly"]
                else "normal"
            ),
            "decision": score["decision"],
            "raw_score": score["raw_score"],
            "raw_threshold": score["raw_threshold"],
            "model_version": score["model_version"],
        }
        self._store_result(
            window.device_id,
            observed_at,
            result,
            window.features,
            self._attack_context(window),
        )


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )
    collector = Collector(Settings.from_env())
    signal.signal(signal.SIGTERM, collector.stop)
    signal.signal(signal.SIGINT, collector.stop)
    collector.start()


if __name__ == "__main__":
    main()
