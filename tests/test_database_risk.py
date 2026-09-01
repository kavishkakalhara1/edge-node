from datetime import UTC, datetime, timedelta

from iot_guard.collector import Collector
from iot_guard.database import Database
from iot_guard.risk import update_risk


def test_database_records_device_and_inference(tmp_path):
    database = Database(tmp_path / "guard.db")
    database.initialize()
    database.upsert_device(
        "iot-1",
        "fingerprint",
        "camera",
        "10.42.0.2",
        mac_address="02:00:00:00:00:01",
    )
    result = {
        "point_score": 3.0,
        "temporal_score": 4.0,
        "ensemble_score": 3.5,
        "point_anomaly": True,
        "temporal_anomaly": False,
        "anomaly_type": "point",
        "decision": "anomaly",
        "raw_score": 3.5,
        "raw_threshold": 2.5,
        "model_version": "gru-svdd-test",
        "attack_context": {
            "basis": "dominant_incoming_peer",
            "attacker": {
                "device_id": "attacker-1",
                "mac_address": "02:00:00:00:00:02",
                "ipv4": "10.42.0.3",
                "hostname": "scanner",
            },
            "victim": {
                "device_id": "iot-1",
                "mac_address": "02:00:00:00:00:01",
                "ipv4": "10.42.0.2",
                "hostname": "camera",
            },
        },
    }
    risk = update_risk(0, None, {**result, "is_anomaly": True, "point_ratio": 2})
    database.record_inference("iot-1", datetime.now(UTC).isoformat(), result, risk)
    database.cleanup(retention_days=30)
    dashboard = database.dashboard()
    assert dashboard["counts"]["total"] == 1
    assert dashboard["devices"][0]["ipv4"] == "10.42.0.2"
    assert dashboard["devices"][0]["mac_address"] == "02:00:00:00:00:01"
    assert dashboard["devices"][0]["risk_score"] > 0
    assert dashboard["recent"][0]["anomaly_type"] == "point"
    assert dashboard["recent"][0]["raw_score"] == 3.5
    assert dashboard["recent"][0]["raw_threshold"] == 2.5
    assert dashboard["recent"][0]["model_version"] == "gru-svdd-test"
    assert dashboard["recent"][0]["attacker"]["ipv4"] == "10.42.0.3"
    assert database.device_detail("iot-1")["events"][0]["attacker"]["hostname"] == "scanner"


def test_daily_reset_clears_current_risk_but_keeps_history(tmp_path):
    database = Database(tmp_path / "guard.db")
    database.initialize()
    database.upsert_device("iot-1", "fingerprint", "camera", "10.42.0.2")
    observed_at = datetime(2026, 8, 12, 23, 55, tzinfo=UTC)
    result = {
        "point_anomaly": True,
        "temporal_anomaly": False,
        "anomaly_type": "point",
        "decision": "anomaly",
    }
    risk = update_risk(
        0.05,
        None,
        {"is_anomaly": True, "gru_score": 0.6, "svdd_score": 0.5},
    )
    database.record_inference("iot-1", observed_at.isoformat(), result, risk)

    assert database.reset_daily_risk(observed_at + timedelta(minutes=10)) == 1
    score, updated_at, consecutive = database.device_risk("iot-1")
    assert (score, updated_at, consecutive) == (0.0, None, 0)
    assert len(database.device_detail("iot-1")["events"]) == 1
    assert database.reset_daily_risk(observed_at + timedelta(minutes=20)) == 0


def test_initialize_migrates_legacy_device_ids_and_history(tmp_path):
    database = Database(tmp_path / "guard.db")
    database.initialize()
    database.upsert_device(
        "iot-legacy",
        "fingerprint",
        "camera",
        "10.42.0.2",
        mac_address="02:00:00:00:00:01",
    )
    database.record_window("iot-legacy", datetime.now(UTC).isoformat(), 2, 1, 64)

    database.initialize()

    assert database.device_detail("iot-legacy") is None
    migrated = database.device_detail("id-020000000001")
    assert migrated is not None
    assert len(migrated["windows"]) == 1


def test_database_returns_latest_captured_features(tmp_path):
    database = Database(tmp_path / "guard.db")
    database.initialize()
    database.upsert_device("iot-1", "fingerprint", "camera", "10.42.0.2")
    features = {
        "network_packets_all_count": 3.0,
        "network_packet-size_avg": 128.5,
    }
    observed_at = datetime.now(UTC).isoformat()

    database.record_window("iot-1", observed_at, 2, 3, 386, features)

    latest = database.device_detail("iot-1")["latest_features"]
    assert latest["window_start"] == observed_at
    assert latest["resolution_seconds"] == 2
    assert latest["values"] == features


def test_initialize_deduplicates_traffic_windows_and_enforces_unique_buckets(tmp_path):
    database = Database(tmp_path / "guard.db")
    database.initialize()
    database.upsert_device("iot-1", "fingerprint", "camera", "10.42.0.2")
    observed_at = datetime.now(UTC).isoformat()
    with database.connect() as connection:
        connection.execute("DROP INDEX idx_windows_device_bucket")
    database.record_window("iot-1", observed_at, 2, 3, 300)
    database.record_window("iot-1", observed_at, 2, 5, 500)

    database.initialize()
    database.record_window("iot-1", observed_at, 2, 4, 400)

    windows = database.device_detail("iot-1")["windows"]
    assert len(windows) == 1
    assert windows[0]["packet_count"] == 5
    assert windows[0]["byte_count"] == 500


def test_report_risk_formula_and_repeat_counter():
    now = datetime.now(UTC)
    risk = update_risk(
        0.05,
        now,
        {"is_anomaly": True, "gru_score": 0.6, "svdd_score": 0.5},
        now=now,
    )
    assert risk.current == 0.46
    assert risk.consecutive_anomalies == 1
    assert risk.level == "medium"

    benign = update_risk(
        risk.current,
        now,
        {"is_anomaly": False},
        now=now,
        consecutive_anomalies=risk.consecutive_anomalies,
    )
    assert abs(benign.current - 0.42) < 1e-12
    assert benign.consecutive_anomalies == 0


def test_point_only_result_accepts_missing_temporal_score():
    collector = Collector.__new__(Collector)
    collector.model = type("Model", (), {"metadata": {
        "point_threshold": 2.0,
        "temporal_threshold": 4.0,
        "ensemble_threshold": 3.0,
    }})()
    ratios = collector._ratios({
        "point_score": 3.0,
        "temporal_score": None,
        "ensemble_score": 3.0,
    })
    assert ratios["point_ratio"] == 1.5
    assert ratios["temporal_ratio"] == 0.0
