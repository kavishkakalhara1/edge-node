from unittest.mock import Mock
from types import SimpleNamespace
from datetime import datetime, timezone

import pytest

from iot_guard.cloud import CloudReporter
from iot_guard.collector import Collector
from iot_guard.config import Settings
from iot_guard.features import WindowRecord
from iot_guard.identity import DeviceIdentity


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


def test_cloud_reporter_suppresses_non_anomaly_payload():
    sender = Mock()
    reporter = CloudReporter("https://cloud.example/report", "eth0", sender=sender)

    assert reporter.submit({"flag": "normal", "device_id": "iot-1"}) is False
    sender.assert_not_called()


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


def test_failed_cloud_delivery_obeys_report_interval(monkeypatch):
    collector = collector_for_reporting()
    collector.cloud = FakeCloud(False)
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
    now = 2.0
    collector._store_result("iot-1", "suppressed", result, {})
    now = 120.0
    collector._store_result("iot-1", "retry", result, {})

    assert len(collector.cloud.payloads) == 2


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


def test_peer_attack_context_and_role_based_healing_target_attacker():
    collector = collector_for_reporting()
    collector.settings = SimpleNamespace(protected_device_macs=())
    collector.identity = DeviceIdentity(b"x" * 32)
    collector.features = SimpleNamespace(
        devices={
            "attacker-id": "02:00:00:00:00:01",
            "victim-id": "02:00:00:00:00:02",
        }
    )
    collector.leases = SimpleNamespace(
        by_mac={
            "02:00:00:00:00:01": SimpleNamespace(
                ipv4="192.168.50.20", hostname="attacker"
            ),
            "02:00:00:00:00:02": SimpleNamespace(
                ipv4="192.168.50.30", hostname="camera"
            ),
        }
    )
    victim_window = WindowRecord(
        device_id="victim-id",
        start=datetime.now(timezone.utc),
        resolution_seconds=2,
        features={"network_packets_dst_count": 20.0, "network_packets_src_count": 2.0},
        packet_count=22,
        byte_count=2200,
        top_incoming_peer_mac="02:00:00:00:00:01",
        top_incoming_peer_ip="192.168.50.20",
    )
    attacker_window = WindowRecord(
        device_id="attacker-id",
        start=datetime.now(timezone.utc),
        resolution_seconds=2,
        features={"network_packets_dst_count": 2.0, "network_packets_src_count": 20.0},
        packet_count=22,
        byte_count=2200,
        top_outgoing_peer_mac="02:00:00:00:00:02",
        top_outgoing_peer_ip="192.168.50.30",
    )

    victim_context = collector._attack_context(victim_window)
    attacker_context = collector._attack_context(attacker_window)

    assert victim_context["attacker"] == attacker_context["attacker"]
    assert victim_context["victim"] == attacker_context["victim"]
    collector._store_result(
        "victim-id",
        "2026-09-01T10:00:00+00:00",
        {
            "point_score": 2.0,
            "temporal_score": None,
            "ensemble_score": 2.0,
            "is_anomaly": True,
            "anomaly_type": "point",
            "decision": "anomaly",
        },
        {},
        victim_context,
    )
    assert collector.cloud.payloads[-1]["attack_context"] == victim_context
    collector._queue_cloud_actions(
        {"actions": [{"action_id": "NET-03", "target": "attacker"}]},
        "2026-09-01T10:00:00+00:00",
        victim_context,
    )
    queued = collector.database.recorded[-1]
    assert queued["device_id"] == "attacker-id"
    assert queued["parameters"]["source_ipv4"] == "192.168.50.20"
    assert queued["parameters"]["victim_device_id"] == "victim-id"


def test_cloud_healing_cannot_target_protected_access_point():
    collector = collector_for_reporting()
    collector.settings = SimpleNamespace(
        protected_device_macs=("38:2c:e5:1d:02:fb",)
    )
    collector.identity = DeviceIdentity(b"x" * 32)
    protected_id = collector.identity.device_id("38:2c:e5:1d:02:fb")

    collector._queue_cloud_actions(
        {"actions": [{"action_id": "SEG-03", "device_id": protected_id}]},
        "2026-09-01T10:00:00+00:00",
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


def collector_for_healing():
    collector = collector_for_reporting()
    collector.active_healings = {}
    collector.healing_auto_unblock_seconds = 60.0
    collector.healing_heartbeat_interval_seconds = 30.0
    return collector


def test_reversible_healing_action_posts_and_resets_throttle(monkeypatch):
    collector = collector_for_healing()
    monkeypatch.setattr("iot_guard.collector.time.monotonic", lambda: 100.0)
    collector.next_anomaly_report_at["iot-1"] = 500.0

    collector._on_healing_completed(
        {
            "request_id": "r1",
            "action_id": "NET-05",
            "device_id": "iot-1",
            "ipv4": "10.42.0.5",
            "mac_address": "02:00:00:00:00:01",
            "parameters": {"ttl_seconds": 300},
            "source": "dashboard",
        },
        {"device_ipv4": "10.42.0.5", "filtered": True},
        None,
    )

    assert "iot-1" not in collector.next_anomaly_report_at
    active = collector.active_healings["iot-1"]
    assert active["action_id"] == "NET-05"
    assert active["unblock_at"] == 160.0
    payload = collector.cloud.payloads[-1]
    assert payload["flag"] == "healing_active"
    assert payload["action_id"] == "NET-05"
    assert payload["auto_unblock_in_seconds"] == 60.0


def test_failed_healing_action_is_not_tracked():
    collector = collector_for_healing()
    collector._on_healing_completed(
        {
            "action_id": "NET-05",
            "device_id": "iot-1",
            "ipv4": "10.42.0.5",
            "parameters": {},
        },
        None,
        "Device is not currently connected",
    )
    assert collector.active_healings == {}
    assert collector.cloud.payloads == []


def test_unblock_completion_clears_state_and_notifies_cloud():
    collector = collector_for_healing()
    collector.active_healings["iot-1"] = {
        "action_id": "NET-05",
        "device_id": "iot-1",
        "ipv4": "10.42.0.5",
        "mac_address": "02:00:00:00:00:01",
        "parameters": {},
        "source": "dashboard",
        "started_at": 0.0,
        "unblock_at": 60.0,
        "next_heartbeat_at": 30.0,
        "unblock_queued": True,
    }
    collector.next_anomaly_report_at["iot-1"] = 999.0

    collector._on_healing_completed(
        {
            "action_id": "UNBLOCK",
            "device_id": "iot-1",
            "source": "auto",
        },
        {"unblocked": True, "removed": []},
        None,
    )

    assert collector.active_healings == {}
    assert "iot-1" not in collector.next_anomaly_report_at
    payload = collector.cloud.payloads[-1]
    assert payload["flag"] == "healing_expired"
    assert payload["action_id"] == "NET-05"
    assert payload["trigger"] == "auto"


def test_maintain_healings_enqueues_auto_unblock_after_60s(monkeypatch):
    collector = collector_for_healing()
    now = 0.0
    monkeypatch.setattr("iot_guard.collector.time.monotonic", lambda: now)

    collector._on_healing_completed(
        {
            "action_id": "NET-05",
            "device_id": "iot-1",
            "ipv4": "10.42.0.5",
            "mac_address": "02:00:00:00:00:01",
            "parameters": {},
            "source": "dashboard",
        },
        {"filtered": True},
        None,
    )
    # Prior to the deadline nothing should be queued.
    now = 59.0
    collector._maintain_healings()
    assert not any(
        entry.get("action_id") == "UNBLOCK"
        for entry in collector.database.recorded
    )

    now = 60.0
    collector._maintain_healings()
    unblock = [
        entry for entry in collector.database.recorded if entry.get("action_id") == "UNBLOCK"
    ]
    assert len(unblock) == 1
    assert unblock[0]["device_id"] == "iot-1"
    assert unblock[0]["source"] == "auto"
    assert collector.active_healings["iot-1"]["unblock_queued"] is True

    # Second sweep must not re-enqueue.
    collector._maintain_healings()
    unblock = [
        entry for entry in collector.database.recorded if entry.get("action_id") == "UNBLOCK"
    ]
    assert len(unblock) == 1


def test_maintain_healings_emits_periodic_heartbeat(monkeypatch):
    collector = collector_for_healing()
    now = 0.0
    monkeypatch.setattr("iot_guard.collector.time.monotonic", lambda: now)

    collector._on_healing_completed(
        {
            "action_id": "NET-05",
            "device_id": "iot-1",
            "ipv4": "10.42.0.5",
            "mac_address": "02:00:00:00:00:01",
            "parameters": {},
            "source": "dashboard",
        },
        {"filtered": True},
        None,
    )
    initial = len(collector.cloud.payloads)
    now = 29.0
    collector._maintain_healings()
    assert len(collector.cloud.payloads) == initial

    now = 30.0
    collector._maintain_healings()
    heartbeat = collector.cloud.payloads[-1]
    assert heartbeat["flag"] == "healing_heartbeat"
    assert heartbeat["device_id"] == "iot-1"
    assert heartbeat["action_id"] == "NET-05"
    assert heartbeat["elapsed_seconds"] == 30.0
    assert heartbeat["remaining_seconds"] == 30.0


def test_cloud_reporter_accepts_healing_flags():
    sender = Mock(return_value={"ok": True})
    reporter = CloudReporter("https://cloud.example/report", "eth0", sender=sender)
    for flag in ("healing_active", "healing_heartbeat", "healing_expired"):
        assert reporter.submit({"flag": flag, "device_id": "iot-1"})
    assert sender.call_count == 3


def test_cloud_reporter_records_each_delivery():
    entries = []

    def sender(payload):
        if payload["flag"] == "healing_heartbeat":
            raise OSError("connection refused")
        return {"accepted": True}

    reporter = CloudReporter(
        "https://cloud.example/report",
        "eth0",
        sender=sender,
        recorder=entries.append,
    )
    reporter.submit({"flag": "anomaly", "device_id": "iot-1"})
    reporter.submit({"flag": "healing_heartbeat", "device_id": "iot-1"})
    reporter.submit({"flag": "normal", "device_id": "iot-1"})

    assert [entry["status"] for entry in entries] == ["accepted", "failed", "suppressed"]
    assert entries[0]["response"] == {"accepted": True}
    assert entries[0]["endpoint"] == "https://cloud.example/report"
    assert entries[0]["duration_ms"] is not None
    assert entries[1]["error"] == "connection refused"
    assert entries[2]["duration_ms"] is None
    assert entries[2]["error"].startswith("unsupported flag")


def test_cloud_reporter_runtime_toggle_controls_delivery():
    state = {"enabled": True}
    sender = Mock(return_value={"accepted": True})
    reporter = CloudReporter(
        "https://cloud.example/report",
        "eth0",
        sender=sender,
        enabled_provider=lambda: state["enabled"],
    )

    assert reporter.submit({"flag": "anomaly", "device_id": "iot-1"})
    state["enabled"] = False
    assert reporter.submit({"flag": "anomaly", "device_id": "iot-1"}) is False
    state["enabled"] = True
    assert reporter.submit({"flag": "anomaly", "device_id": "iot-1"})
    assert sender.call_count == 2
