from __future__ import annotations

import logging
import signal
import threading
import time
from collections import defaultdict, deque
from datetime import timezone

from .capture import CaptureService
from .config import Settings
from .database import Database
from .features import FeatureEngine, PacketObservation, WindowRecord
from .identity import DeviceIdentity
from .leases import LeaseRegistry
from .model import ProductionEnsemble
from .risk import update_risk

LOGGER = logging.getLogger(__name__)


class Collector:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.database = Database(settings.database_path)
        self.identity = DeviceIdentity.from_file(settings.identity_secret_file)
        self.leases = LeaseRegistry(settings.dhcp_lease_file, self.identity)
        self.model = ProductionEnsemble(settings.artifact_dir)
        self.temporal: dict[str, deque[dict[str, float]]] = defaultdict(
            lambda: deque(maxlen=self.model.metadata["temporal_input_windows"])
        )
        self.latest_point: dict[str, tuple[float, dict[str, float]]] = {}
        self.features = FeatureEngine(self._window_ready)
        self.capture = CaptureService(
            settings.capture_interfaces, self.leases, self._packet_ready
        )
        self.stop_event = threading.Event()
        self.last_cleanup = 0.0

    def start(self) -> None:
        self.database.initialize()
        self.refresh_devices()
        self.capture.start()
        LOGGER.info("Collector started with model artifact %s", self.model.metadata["artifact_version"])
        try:
            while not self.stop_event.wait(1.0):
                now = time.time()
                self.features.tick(now)
                self.refresh_devices()
                if now - self.last_cleanup >= 3600:
                    self.database.cleanup(self.settings.retention_days)
                    self.last_cleanup = now
        finally:
            self.capture.stop()
            LOGGER.info("Collector stopped")

    def stop(self, *_args) -> None:
        self.stop_event.set()

    def refresh_devices(self) -> None:
        leases = self.leases.refresh()
        now = time.time()
        active_ids = set()
        for lease in leases:
            active_ids.add(lease.device_id)
            self.database.upsert_device(
                lease.device_id, lease.mac_fingerprint, lease.hostname, lease.ipv4
            )
            self.features.register_device(lease.device_id, lease.mac, now)
        self.features.unregister_missing(active_ids)
        self.database.mark_disconnected_except(active_ids)

    def _packet_ready(self, device_id: str, packet: PacketObservation) -> None:
        self.features.ingest(device_id, packet)

    def _ratios(self, result: dict) -> dict:
        return {
            **result,
            "point_ratio": float(result.get("point_score") or 0.0)
            / max(float(self.model.metadata["point_threshold"]), 1e-9),
            "temporal_ratio": float(result.get("temporal_score") or 0.0)
            / max(float(self.model.metadata["temporal_threshold"]), 1e-9),
            "fused_ratio": float(result.get("ensemble_score") or 0.0)
            / max(float(self.model.metadata["ensemble_threshold"]), 1e-9),
        }

    def _store_result(self, device_id: str, observed_at: str, result: dict) -> None:
        enriched = self._ratios(result)
        current, updated_at = self.database.device_risk(device_id)
        risk = update_risk(
            current,
            updated_at,
            enriched,
            half_life_hours=self.settings.risk_half_life_hours,
        )
        self.database.record_inference(device_id, observed_at, enriched, risk)
        if enriched.get("is_anomaly"):
            LOGGER.warning(
                "Anomaly device=%s type=%s risk=%.1f",
                device_id,
                enriched.get("anomaly_type"),
                risk.current,
            )

    def _window_ready(self, window: WindowRecord) -> None:
        observed_at = window.start.astimezone(timezone.utc).isoformat()
        self.database.record_window(
            window.device_id,
            observed_at,
            window.resolution_seconds,
            window.packet_count,
            window.byte_count,
        )
        if window.resolution_seconds == 2:
            self.latest_point[window.device_id] = (window.start.timestamp(), window.features)
            point = self.model.score_point(window.features)
            point_result = {
                **point,
                "temporal_score": None,
                "temporal_anomaly": False,
                "ensemble_score": point["point_score"],
                "fused_score_anomaly": False,
                "is_anomaly": point["point_anomaly"],
                "anomaly_type": "point" if point["point_anomaly"] else "normal",
                "decision": "anomaly" if point["point_anomaly"] else "normal",
            }
            self._store_result(window.device_id, observed_at, point_result)
            return
        temporal = self.temporal[window.device_id]
        temporal.append(window.features)
        latest = self.latest_point.get(window.device_id)
        if latest is None or len(temporal) < temporal.maxlen:
            return
        point_time, point_features = latest
        if abs(window.start.timestamp() - point_time) > 12:
            LOGGER.debug("Skipping stale point/temporal pair for %s", window.device_id)
            return
        result = self.model.score_windows(point_features, list(temporal))
        self._store_result(window.device_id, observed_at, result)


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
