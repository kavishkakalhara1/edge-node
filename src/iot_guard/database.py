from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

from .identity import normalize_mac

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    mac_fingerprint TEXT NOT NULL UNIQUE,
    mac_address TEXT,
    hostname TEXT,
    ipv4 TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    connected INTEGER NOT NULL DEFAULT 1,
    risk_score REAL NOT NULL DEFAULT 0,
    risk_level TEXT NOT NULL DEFAULT 'low',
    risk_updated_at TEXT,
    risk_date TEXT,
    consecutive_anomalies INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS anomaly_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    observed_at TEXT NOT NULL,
    point_score REAL,
    temporal_score REAL,
    ensemble_score REAL,
    point_anomaly INTEGER NOT NULL DEFAULT 0,
    temporal_anomaly INTEGER NOT NULL DEFAULT 0,
    anomaly_type TEXT NOT NULL,
    decision TEXT NOT NULL,
    raw_score REAL,
    raw_threshold REAL,
    model_version TEXT,
    risk_before REAL NOT NULL,
    risk_after REAL NOT NULL,
    details_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_events_device_time
ON anomaly_events(device_id, observed_at DESC);
CREATE TABLE IF NOT EXISTS traffic_windows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    window_start TEXT NOT NULL,
    resolution_seconds INTEGER NOT NULL,
    packet_count INTEGER NOT NULL,
    byte_count INTEGER NOT NULL,
    features_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_windows_device_time
ON traffic_windows(device_id, window_start DESC);
CREATE TABLE IF NOT EXISTS service_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    level TEXT NOT NULL,
    component TEXT NOT NULL,
    message TEXT NOT NULL,
    details_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS healing_action_requests (
    request_id TEXT PRIMARY KEY,
    action_id TEXT NOT NULL,
    device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'queued',
    requested_at TEXT NOT NULL,
    started_at TEXT,
    completed_at TEXT,
    parameters_json TEXT NOT NULL DEFAULT '{}',
    result_json TEXT,
    error TEXT
);
CREATE INDEX IF NOT EXISTS idx_healing_requests_status_time
ON healing_action_requests(status, requested_at);
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Database:
    def __init__(self, path: Path):
        self.path = path

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=15)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 15000")
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = NORMAL")
            connection.executescript(SCHEMA)
            columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(anomaly_events)")
            }
            if "raw_threshold" not in columns:
                connection.execute("ALTER TABLE anomaly_events ADD COLUMN raw_threshold REAL")
            if "model_version" not in columns:
                connection.execute("ALTER TABLE anomaly_events ADD COLUMN model_version TEXT")
            if "raw_score" not in columns:
                connection.execute("ALTER TABLE anomaly_events ADD COLUMN raw_score REAL")
            device_columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(devices)")
            }
            if "risk_date" not in device_columns:
                connection.execute("ALTER TABLE devices ADD COLUMN risk_date TEXT")
            if "consecutive_anomalies" not in device_columns:
                connection.execute(
                    "ALTER TABLE devices ADD COLUMN consecutive_anomalies INTEGER NOT NULL DEFAULT 0"
                )
            if "mac_address" not in device_columns:
                connection.execute("ALTER TABLE devices ADD COLUMN mac_address TEXT")
            window_columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(traffic_windows)")
            }
            if "features_json" not in window_columns:
                connection.execute(
                    "ALTER TABLE traffic_windows ADD COLUMN features_json TEXT NOT NULL DEFAULT '{}'"
                )
            connection.commit()
            self._migrate_device_ids(connection)

    @staticmethod
    def _migrate_device_ids(connection: sqlite3.Connection) -> None:
        migrations = []
        for row in connection.execute(
            "SELECT device_id, mac_address FROM devices WHERE mac_address IS NOT NULL"
        ):
            new_id = f"id-{normalize_mac(row['mac_address']).replace(':', '')}"
            if row["device_id"] != new_id:
                migrations.append((row["device_id"], new_id))
        if not migrations:
            return

        connection.execute("PRAGMA foreign_keys = OFF")
        try:
            connection.execute("BEGIN")
            for old_id, new_id in migrations:
                existing = connection.execute(
                    "SELECT device_id FROM devices WHERE device_id = ?", (new_id,)
                ).fetchone()
                if existing is not None:
                    raise RuntimeError(f"Cannot migrate {old_id}: {new_id} already exists")
                for table in ("anomaly_events", "traffic_windows", "healing_action_requests"):
                    connection.execute(
                        f"UPDATE {table} SET device_id = ? WHERE device_id = ?",
                        (new_id, old_id),
                    )
                connection.execute(
                    "UPDATE devices SET device_id = ? WHERE device_id = ?", (new_id, old_id)
                )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.execute("PRAGMA foreign_keys = ON")

    def upsert_device(
        self,
        device_id: str,
        mac_fingerprint: str,
        hostname: str | None,
        ipv4: str | None,
        mac_address: str | None = None,
    ) -> None:
        now = utc_now()
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO devices(
                    device_id, mac_fingerprint, mac_address, hostname, ipv4, first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    mac_address = COALESCE(excluded.mac_address, devices.mac_address),
                    hostname = COALESCE(excluded.hostname, devices.hostname),
                    ipv4 = COALESCE(excluded.ipv4, devices.ipv4),
                    last_seen = excluded.last_seen,
                    connected = 1
                """,
                (device_id, mac_fingerprint, mac_address, hostname, ipv4, now, now),
            )

    def mark_disconnected_except(self, active_ids: set[str]) -> None:
        with self.connect() as connection:
            if not active_ids:
                connection.execute("UPDATE devices SET connected = 0")
                return
            placeholders = ",".join("?" for _ in active_ids)
            connection.execute(
                f"UPDATE devices SET connected = 0 WHERE device_id NOT IN ({placeholders})",
                tuple(active_ids),
            )

    def device_risk(self, device_id: str) -> tuple[float, datetime | None, int]:
        with self.connect() as connection:
            row = connection.execute(
                """SELECT risk_score, risk_updated_at, consecutive_anomalies
                FROM devices WHERE device_id = ?""",
                (device_id,),
            ).fetchone()
        if row is None:
            return 0.0, None, 0
        updated = datetime.fromisoformat(row["risk_updated_at"]) if row["risk_updated_at"] else None
        return float(row["risk_score"]), updated, int(row["consecutive_anomalies"])

    def record_inference(self, device_id: str, observed_at: str, result: dict, risk) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                UPDATE devices SET risk_score = ?, risk_level = ?, risk_updated_at = ?,
                    risk_date = ?, consecutive_anomalies = ?, last_seen = ?
                WHERE device_id = ?
                """,
                (
                    risk.current,
                    risk.level,
                    observed_at,
                    datetime.fromisoformat(observed_at).astimezone(timezone.utc).date().isoformat(),
                    risk.consecutive_anomalies,
                    observed_at,
                    device_id,
                ),
            )
            connection.execute(
                """
                INSERT INTO anomaly_events(
                    device_id, observed_at, point_score, temporal_score, ensemble_score,
                    point_anomaly, temporal_anomaly, anomaly_type, decision,
                    raw_score, raw_threshold, model_version, risk_before, risk_after, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    device_id,
                    observed_at,
                    result.get("point_score"),
                    result.get("temporal_score"),
                    result.get("ensemble_score"),
                    int(bool(result.get("point_anomaly"))),
                    int(bool(result.get("temporal_anomaly"))),
                    result.get("anomaly_type", "normal"),
                    result.get("decision", "normal"),
                    result.get("raw_score"),
                    result.get("raw_threshold"),
                    result.get("model_version"),
                    risk.previous,
                    risk.current,
                    json.dumps({"severity": risk.severity}, separators=(",", ":")),
                ),
            )

    def record_window(
        self,
        device_id: str,
        window_start: str,
        resolution: int,
        packets: int,
        byte_count: int,
        features: dict[str, float] | None = None,
    ) -> None:
        with self.connect() as connection:
            connection.execute(
                """INSERT INTO traffic_windows(
                    device_id, window_start, resolution_seconds, packet_count, byte_count,
                    features_json
                ) VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    device_id,
                    window_start,
                    resolution,
                    packets,
                    byte_count,
                    json.dumps(features or {}, separators=(",", ":")),
                ),
            )

    def log(self, level: str, component: str, message: str, details: dict | None = None) -> None:
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO service_logs(created_at, level, component, message, details_json) VALUES (?, ?, ?, ?, ?)",
                (utc_now(), level, component, message, json.dumps(details or {})),
            )

    def create_healing_request(
        self, request_id: str, action_id: str, device_id: str, parameters: dict
    ) -> dict | None:
        now = utc_now()
        with self.connect() as connection:
            device = connection.execute(
                "SELECT device_id FROM devices WHERE device_id = ?", (device_id,)
            ).fetchone()
            if device is None:
                return None
            connection.execute(
                """INSERT INTO healing_action_requests(
                    request_id, action_id, device_id, requested_at, parameters_json
                ) VALUES (?, ?, ?, ?, ?)""",
                (request_id, action_id, device_id, now, json.dumps(parameters)),
            )
        return self.healing_request(request_id)

    def healing_request(self, request_id: str) -> dict | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM healing_action_requests WHERE request_id = ?", (request_id,)
            ).fetchone()
        return self._healing_request_dict(row) if row is not None else None

    def claim_healing_request(self) -> dict | None:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT r.*, d.ipv4, d.connected FROM healing_action_requests r
                JOIN devices d USING(device_id)
                WHERE r.status = 'queued' ORDER BY r.requested_at LIMIT 1"""
            ).fetchone()
            if row is None:
                return None
            started_at = utc_now()
            connection.execute(
                """UPDATE healing_action_requests SET status = 'running', started_at = ?
                WHERE request_id = ? AND status = 'queued'""",
                (started_at, row["request_id"]),
            )
        claimed = dict(row)
        claimed["status"] = "running"
        claimed["started_at"] = started_at
        claimed["parameters"] = json.loads(claimed.pop("parameters_json"))
        return claimed

    def complete_healing_request(
        self, request_id: str, status: str, result: dict | None = None, error: str | None = None
    ) -> None:
        if status not in {"succeeded", "failed"}:
            raise ValueError(f"Invalid terminal healing action status: {status}")
        with self.connect() as connection:
            connection.execute(
                """UPDATE healing_action_requests
                SET status = ?, completed_at = ?, result_json = ?, error = ?
                WHERE request_id = ? AND status = 'running'""",
                (
                    status,
                    utc_now(),
                    json.dumps(result) if result is not None else None,
                    error,
                    request_id,
                ),
            )

    @staticmethod
    def _healing_request_dict(row: sqlite3.Row) -> dict:
        item = dict(row)
        item["parameters"] = json.loads(item.pop("parameters_json"))
        item["result"] = json.loads(item.pop("result_json")) if item["result_json"] else None
        return item

    def dashboard(self) -> dict:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        with self.connect() as connection:
            devices = [dict(row) for row in connection.execute(
                """SELECT d.*,
                    (SELECT COUNT(*) FROM anomaly_events e
                     WHERE e.device_id = d.device_id AND e.decision = 'anomaly'
                     AND e.observed_at >= ?) AS anomalies_24h
                    FROM devices d ORDER BY d.risk_score DESC, d.last_seen DESC""",
                (cutoff,),
            )]
            counts = dict(connection.execute(
                """SELECT COUNT(*) AS total,
                    SUM(connected) AS connected,
                    SUM(CASE WHEN risk_score >= 0.50 THEN 1 ELSE 0 END) AS elevated
                    FROM devices"""
            ).fetchone())
            recent = [dict(row) for row in connection.execute(
                """SELECT e.*, d.hostname, d.ipv4 FROM anomaly_events e
                    JOIN devices d USING(device_id) WHERE e.decision = 'anomaly'
                    ORDER BY e.observed_at DESC LIMIT 50"""
            )]
        return {"devices": devices, "counts": counts, "recent": recent}

    def device_detail(self, device_id: str) -> dict | None:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM devices WHERE device_id = ?", (device_id,)
            ).fetchone()
            if row is None:
                return None
            events = [dict(item) for item in connection.execute(
                "SELECT * FROM anomaly_events WHERE device_id = ? ORDER BY observed_at DESC LIMIT 200",
                (device_id,),
            )]
            windows = [dict(item) for item in connection.execute(
                """SELECT id, device_id, window_start, resolution_seconds,
                    packet_count, byte_count FROM traffic_windows
                WHERE device_id = ? ORDER BY window_start DESC LIMIT 100""",
                (device_id,),
            )]
            latest_features_row = connection.execute(
                """SELECT window_start, resolution_seconds, features_json
                FROM traffic_windows WHERE device_id = ? AND features_json <> '{}'
                ORDER BY window_start DESC, resolution_seconds ASC LIMIT 1""",
                (device_id,),
            ).fetchone()
            traffic = dict(connection.execute(
                """SELECT COUNT(*) AS window_count,
                    COALESCE(SUM(packet_count), 0) AS packet_count,
                    COALESCE(SUM(byte_count), 0) AS byte_count,
                    MAX(window_start) AS latest_window
                FROM traffic_windows WHERE device_id = ? AND window_start >= ?""",
                (device_id, cutoff),
            ).fetchone())
        for window in windows:
            resolution = max(int(window["resolution_seconds"]), 1)
            window["packets_per_second"] = window["packet_count"] / resolution
            window["bytes_per_second"] = window["byte_count"] / resolution
        latest_features = None
        if latest_features_row is not None:
            latest_features = {
                "window_start": latest_features_row["window_start"],
                "resolution_seconds": latest_features_row["resolution_seconds"],
                "values": json.loads(latest_features_row["features_json"]),
            }
        return {
            "device": dict(row),
            "events": events,
            "windows": windows,
            "traffic": traffic,
            "latest_features": latest_features,
        }

    def reset_daily_risk(self, now: datetime | None = None) -> int:
        current_date = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).date().isoformat()
        with self.connect() as connection:
            cursor = connection.execute(
                """UPDATE devices SET risk_score = 0, risk_level = 'low',
                    risk_updated_at = NULL, risk_date = ?, consecutive_anomalies = 0
                WHERE risk_date IS NULL OR risk_date <> ?""",
                (current_date, current_date),
            )
        return cursor.rowcount

    def cleanup(self, retention_days: int) -> None:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
        with self.connect() as connection:
            connection.execute("DELETE FROM traffic_windows WHERE window_start < ?", (cutoff,))
            connection.execute("DELETE FROM anomaly_events WHERE observed_at < ?", (cutoff,))
            connection.execute("DELETE FROM service_logs WHERE created_at < ?", (cutoff,))
        with self.connect() as connection:
            connection.execute("PRAGMA wal_checkpoint(PASSIVE)")
