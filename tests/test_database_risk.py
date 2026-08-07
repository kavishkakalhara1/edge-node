from datetime import datetime, timezone

from iot_guard.database import Database
from iot_guard.collector import Collector
from iot_guard.risk import update_risk


def test_database_records_device_and_inference(tmp_path):
    database = Database(tmp_path / "guard.db")
    database.initialize()
    database.upsert_device("iot-1", "fingerprint", "camera", "10.42.0.2")
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
    }
    risk = update_risk(0, None, {**result, "is_anomaly": True, "point_ratio": 2})
    database.record_inference("iot-1", datetime.now(timezone.utc).isoformat(), result, risk)
    database.cleanup(retention_days=30)
    dashboard = database.dashboard()
    assert dashboard["counts"]["total"] == 1
    assert dashboard["devices"][0]["risk_score"] > 0
    assert dashboard["recent"][0]["anomaly_type"] == "point"
    assert dashboard["recent"][0]["raw_score"] == 3.5
    assert dashboard["recent"][0]["raw_threshold"] == 2.5
    assert dashboard["recent"][0]["model_version"] == "gru-svdd-test"


def test_normal_observation_decays_risk():
    now = datetime.now(timezone.utc)
    risk = update_risk(50, now, {"is_anomaly": False}, now=now)
    assert risk.current < 50
    assert risk.level in {"medium", "high"}


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
