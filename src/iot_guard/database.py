from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    mac_fingerprint TEXT NOT NULL UNIQUE,
    hostname TEXT,
    ipv4 TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    connected INTEGER NOT NULL DEFAULT 1,
    risk_score REAL NOT NULL DEFAULT 0,
    risk_level TEXT NOT NULL DEFAULT 'low',
    risk_updated_at TEXT
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
    byte_count INTEGER NOT NULL
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

    def upsert_device(
        self, device_id: str, mac_fingerprint: str, hostname: str | None, ipv4: str | None
    ) -> None:
        now = utc_now()
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO devices(device_id, mac_fingerprint, hostname, ipv4, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    hostname = COALESCE(excluded.hostname, devices.hostname),
                    ipv4 = COALESCE(excluded.ipv4, devices.ipv4),
                    last_seen = excluded.last_seen,
                    connected = 1
                """,
                (device_id, mac_fingerprint, hostname, ipv4, now, now),
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

    def device_risk(self, device_id: str) -> tuple[float, datetime | None]:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT risk_score, risk_updated_at FROM devices WHERE device_id = ?", (device_id,)
            ).fetchone()
        if row is None:
            return 0.0, None
        updated = datetime.fromisoformat(row["risk_updated_at"]) if row["risk_updated_at"] else None
        return float(row["risk_score"]), updated

    def record_inference(self, device_id: str, observed_at: str, result: dict, risk) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                UPDATE devices SET risk_score = ?, risk_level = ?, risk_updated_at = ?, last_seen = ?
                WHERE device_id = ?
                """,
                (risk.current, risk.level, observed_at, observed_at, device_id),
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
        self, device_id: str, window_start: str, resolution: int, packets: int, byte_count: int
    ) -> None:
        with self.connect() as connection:
            connection.execute(
                """INSERT INTO traffic_windows(
                    device_id, window_start, resolution_seconds, packet_count, byte_count
                ) VALUES (?, ?, ?, ?, ?)""",
                (device_id, window_start, resolution, packets, byte_count),
            )

    def log(self, level: str, component: str, message: str, details: dict | None = None) -> None:
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO service_logs(created_at, level, component, message, details_json) VALUES (?, ?, ?, ?, ?)",
                (utc_now(), level, component, message, json.dumps(details or {})),
            )

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
                    SUM(CASE WHEN risk_score >= 50 THEN 1 ELSE 0 END) AS elevated
                    FROM devices"""
            ).fetchone())
            recent = [dict(row) for row in connection.execute(
                """SELECT e.*, d.hostname, d.ipv4 FROM anomaly_events e
                    JOIN devices d USING(device_id) WHERE e.decision = 'anomaly'
                    ORDER BY e.observed_at DESC LIMIT 50"""
            )]
        return {"devices": devices, "counts": counts, "recent": recent}

    def device_detail(self, device_id: str) -> dict | None:
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
                "SELECT * FROM traffic_windows WHERE device_id = ? ORDER BY window_start DESC LIMIT 100",
                (device_id,),
            )]
        return {"device": dict(row), "events": events, "windows": windows}

    def cleanup(self, retention_days: int) -> None:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
        with self.connect() as connection:
            connection.execute("DELETE FROM traffic_windows WHERE window_start < ?", (cutoff,))
            connection.execute("DELETE FROM anomaly_events WHERE observed_at < ?", (cutoff,))
            connection.execute("DELETE FROM service_logs WHERE created_at < ?", (cutoff,))
        with self.connect() as connection:
            connection.execute("PRAGMA wal_checkpoint(PASSIVE)")
