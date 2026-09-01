from unittest.mock import Mock

import pytest

from iot_guard.cloud import CloudReporter
from iot_guard.collector import Collector
from iot_guard.config import Settings


class FakeDatabase:
    def __init__(self):
        self.recorded = []

    def device_risk(self, _device_id):
        return 0.05, None, 0

    def record_inference(self, device_id, observed_at, result, risk):
        self.recorded.append((device_id, observed_at, result, risk))

    def create_healing_request(
        self, request_id, action_id, device_id, parameters, source="dashboard"
    ):
        request = {
            "request_id": request_id,
            "action_id": action_id,
            "device_id": device_id,
            "parameters": parameters,
            "source": source,
        }
        self.recorded.append(request)
        return request


class FakeCloud:
    def __init__(self, response=True):
        self.payloads = []
        self.response = response

    def submit(self, payload):
        self.payloads.append(payload)
        return self.response


def collector_for_reporting():
    collector = Collector.__new__(Collector)
    collector.database = FakeDatabase()
    collector.cloud = FakeCloud()
    collector.next_anomaly_report_at = {}
    collector.anomaly_report_interval_seconds = 120.0
    collector.model = type(
        "Model",
        (),
        {
            "metadata": {
                "point_threshold": 1.0,
                "temporal_threshold": 1.0,
                "ensemble_threshold": 1.0,
            }
        },
    )()
    return collector


def test_anomaly_posts_requested_payload_with_all_features():
    collector = collector_for_reporting()
    features = {"network_packets_all_count": 12.0, "network_ttl_avg": 63.5}
    collector._store_result(
        "iot-1",
        "2026-08-13T10:00:00+00:00",
        {
            "point_score": 2.0,
            "temporal_score": None,
            "ensemble_score": 2.0,
            "is_anomaly": True,
            "anomaly_type": "point",
            "decision": "anomaly",
        },
        features,
    )

    payload = collector.cloud.payloads[0]
    assert payload["flag"] == "anomaly"
    assert payload["risk_score"] > 0.05
    assert payload["network_features"] == features
    assert payload["device_id"] == "iot-1"


def test_benign_result_is_not_posted():
    collector = collector_for_reporting()
    collector._store_result(
        "iot-1",
        "2026-08-13T10:00:00+00:00",
        {
            "point_score": 0.2,
            "temporal_score": None,
            "ensemble_score": 0.2,
            "is_anomaly": False,
            "anomaly_type": "normal",
            "decision": "normal",
        },
        {"network_packets_all_count": 1.0},
    )
    assert collector.cloud.payloads == []


def test_anomaly_reporting_waits_two_minutes_per_device(monkeypatch):
    collector = collector_for_reporting()
    now = 0.0
    monkeypatch.setattr("iot_guard.collector.time.monotonic", lambda: now)
    result = {
        "point_score": 2.0,
        "temporal_score": None,
        "ensemble_score": 2.0,
        "is_anomaly": True,
        "anomaly_type": "point",
        "decision": "anomaly",
    }

    collector._store_result("iot-1", "first", result, {})
    now = 119.0
    collector._store_result("iot-1", "suppressed", result, {})
    collector._store_result("iot-2", "independent", result, {})
    now = 120.0
    collector._store_result("iot-1", "eligible", result, {})

    assert [payload["device_id"] for payload in collector.cloud.payloads] == [
        "iot-1",
        "iot-2",
        "iot-1",
    ]


def test_cloud_response_queues_supported_healing_action():
    collector = collector_for_reporting()
    collector.cloud = FakeCloud(
        {
            "status": "accepted",
            "actions": [
                {
                    "action_id": "NET-03",
                    "device_id": "iot-1",
                    "parameters": {"ttl_seconds": 300},
                    "attacker_ip": "192.0.2.8",
                }
            ],
        }
    )

    collector._store_result(
        "iot-1",
        "2026-08-13T10:00:00+00:00",
        {
            "point_score": 2.0,
            "temporal_score": None,
            "ensemble_score": 2.0,
            "is_anomaly": True,
            "anomaly_type": "point",
            "decision": "anomaly",
        },
        {},
    )

    queued = collector.database.recorded[-1]
    assert queued["action_id"] == "NET-03"
    assert queued["device_id"] == "iot-1"
    assert queued["source"] == "cloud"
    assert queued["parameters"] == {
        "ttl_seconds": 300,
        "attacker_ip": "192.0.2.8",
    }


def test_cloud_response_ignores_unsupported_healing_action():
    collector = collector_for_reporting()
    collector._queue_cloud_actions(
        {
            "actions": [
                {"action_id": "ACC-03", "device_id": "iot-1"},
                {"action_id": "SEG-03"},
            ]
        },
        "2026-08-13T10:00:00+00:00",
    )

    assert collector.database.recorded == []


def test_reporter_waits_for_delivery_and_blank_endpoint_disables_it():
    received = []

    def sender(payload):
        received.append(payload)
        return {"accepted": True}

    payload = {
        "flag": "anomaly",
        "risk_score": 0.46,
        "network_features": {"network_packets_all_count": 12.0},
        "device_id": "iot-1",
    }
    reporter = CloudReporter("https://cloud.example/anomalies", "eth0", sender=sender)
    assert reporter.submit(payload)
    reporter.close()
    assert received == [payload]
    assert not CloudReporter("", "eth0").submit(payload)


def test_cloud_post_uses_configured_uplink_interface():
    response = Mock(status=202)
    response.read.return_value = b'{"accepted":true}'
    connection = Mock()
    connection.getresponse.return_value = response
    factory = Mock(return_value=connection)
    reporter = CloudReporter(
        "https://cloud.example/api/anomalies?site=edge",
        "eth0",
        token="secret",
        connection_factory=factory,
    )
    result = reporter._post({"flag": "anomaly", "device_id": "iot-1"})

    assert result == {"accepted": True}
    target, interface, timeout = factory.call_args.args
    assert target.hostname == "cloud.example"
    assert interface == "eth0"
    assert timeout == 30.0
    connection.request.assert_called_once()
    method, path = connection.request.call_args.args[:2]
    assert (method, path) == ("POST", "/api/anomalies?site=edge")
    assert connection.request.call_args.kwargs["headers"]["Authorization"] == "Bearer secret"


def test_cloud_uplink_cannot_reuse_iot_hotspot(monkeypatch):
    monkeypatch.setenv("IOT_GUARD_CLOUD_API_ENDPOINT", "https://cloud.example/anomalies")
    monkeypatch.setenv("IOT_GUARD_CLOUD_UPLINK_INTERFACE", "wlan0")
    monkeypatch.setenv("IOT_GUARD_HOTSPOT_INTERFACE", "wlan0")
    with pytest.raises(ValueError, match="different interfaces"):
        Settings.from_env()