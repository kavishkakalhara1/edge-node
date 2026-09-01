from dataclasses import replace
from datetime import UTC, datetime

from fastapi.testclient import TestClient

from iot_guard import web
from iot_guard.database import Database
from iot_guard.healing import SUPPORTED_ACTIONS
from iot_guard.risk import update_risk


def client_for(tmp_path, monkeypatch):
    database = Database(tmp_path / "guard.db")
    monkeypatch.setattr(web, "database", database)
    monkeypatch.setattr(web, "settings", replace(web.settings, healing_api_token="test-token"))
    return TestClient(web.app), database


def test_sri_lanka_time_filters_convert_utc():
    timestamp = "2026-08-31T14:55:54+00:00"

    assert web.sl_datetime(timestamp) == "2026-08-31 20:25:54"
    assert web.sl_time(timestamp) == "20:25:54"


def test_dashboard_shows_connected_device_addresses(tmp_path, monkeypatch):
    client, database = client_for(tmp_path, monkeypatch)
    with client:
        database.upsert_device(
            "iot-1",
            "fingerprint",
            "camera",
            "10.42.0.2",
            mac_address="02:00:00:00:00:01",
        )

        response = client.get("/")

    assert response.status_code == 200
    assert "10.42.0.2" in response.text
    assert "02:00:00:00:00:01" in response.text
    assert "online" in response.text


def test_dashboard_omits_ignored_device_mac(tmp_path, monkeypatch):
    client, database = client_for(tmp_path, monkeypatch)
    monkeypatch.setattr(
        web,
        "settings",
        replace(web.settings, ignored_device_macs=("38:2c:e5:1d:02:fb",)),
    )
    with client:
        database.upsert_device(
            "ignored-device",
            "ignored-fingerprint",
            "wlan1",
            "192.168.50.67",
            mac_address="38:2c:e5:1d:02:fb",
        )
        database.upsert_device(
            "visible-device",
            "visible-fingerprint",
            "camera",
            "192.168.50.68",
            mac_address="02:00:00:00:00:01",
        )

        response = client.get("/")
        api_response = client.get("/api/devices")

    assert response.status_code == 200
    assert "192.168.50.67" not in response.text
    assert "38:2c:e5:1d:02:fb" not in response.text
    assert "192.168.50.68" in response.text
    assert api_response.json()["counts"]["total"] == 1
    assert [device["device_id"] for device in api_response.json()["devices"]] == [
        "visible-device"
    ]


def test_dashboards_show_suspected_attacker_details(tmp_path, monkeypatch):
    client, database = client_for(tmp_path, monkeypatch)
    with client:
        database.upsert_device("victim", "victim-fingerprint", "camera", "10.42.0.30")
        result = {
            "point_anomaly": True,
            "temporal_anomaly": False,
            "is_anomaly": True,
            "anomaly_type": "point",
            "decision": "anomaly",
            "attack_context": {
                "basis": "dominant_incoming_peer",
                "attacker": {
                    "device_id": "attacker",
                    "mac_address": "02:00:00:00:00:01",
                    "ipv4": "10.42.0.20",
                    "hostname": "scanner",
                },
                "victim": {
                    "device_id": "victim",
                    "mac_address": "02:00:00:00:00:02",
                    "ipv4": "10.42.0.30",
                    "hostname": "camera",
                },
            },
        }
        risk = update_risk(0, None, result)
        database.record_inference("victim", datetime.now(UTC).isoformat(), result, risk)

        dashboard = client.get("/")
        device_page = client.get("/devices/victim")

    assert "Suspected attacker" in dashboard.text
    assert "scanner" in dashboard.text
    assert "10.42.0.20" in device_page.text
    assert "02:00:00:00:00:01" in device_page.text


def test_device_detail_returns_monitored_traffic(tmp_path, monkeypatch):
    client, database = client_for(tmp_path, monkeypatch)
    with client:
        database.upsert_device("iot-1", "fingerprint", "camera", "10.42.0.2")
        database.record_window(
            "iot-1",
            datetime.now(UTC).isoformat(),
            2,
            12,
            4096,
            {
                "network_packets_all_count": 12.0,
                "network_ttl_avg": 63.5,
            },
        )

        response = client.get("/api/devices/iot-1")
        page = client.get("/devices/iot-1")

    assert response.status_code == 200
    data = response.json()
    assert data["traffic"]["window_count"] == 1
    assert data["traffic"]["packet_count"] == 12
    assert data["traffic"]["byte_count"] == 4096
    assert data["windows"][0]["packets_per_second"] == 6
    assert data["windows"][0]["bytes_per_second"] == 2048
    assert page.status_code == 200
    assert "Monitored traffic" in page.text
    assert "4,096" in page.text
    assert "6.00 pkt/s" in page.text
    assert "Live model features" in page.text
    assert "network_packets_all_count" in page.text
    assert ">12<" in page.text
    assert "network_ttl_avg" in page.text
    assert ">63.5<" in page.text


def test_device_detail_does_not_double_count_overlapping_resolutions(tmp_path, monkeypatch):
    client, database = client_for(tmp_path, monkeypatch)
    observed_at = datetime.now(UTC).isoformat()
    with client:
        database.upsert_device("iot-1", "fingerprint", "camera", "10.42.0.2")
        database.record_window("iot-1", observed_at, 2, 12, 4096)
        database.record_window("iot-1", observed_at, 10, 60, 20480)
        response = client.get("/api/devices/iot-1")

    traffic = response.json()["traffic"]
    assert traffic["window_count"] == 1
    assert traffic["packet_count"] == 12
    assert traffic["byte_count"] == 4096


def test_post_healing_action_queues_request(tmp_path, monkeypatch):
    client, database = client_for(tmp_path, monkeypatch)
    with client:
        database.upsert_device("iot-1", "fingerprint", "camera", "10.42.0.2")
        response = client.post(
            "/api/devices/iot-1/healing-actions/NET-03",
            headers={"X-IoT-Guard-Token": "test-token"},
            json={"parameters": {"source_ipv4": "192.0.2.8", "ttl_seconds": 300}},
        )
        assert response.status_code == 202
        request = response.json()
        assert request["action_id"] == "NET-03"
        assert request["status"] == "queued"

        status_response = client.get(
            f"/api/healing-actions/{request['request_id']}",
            headers={"X-IoT-Guard-Token": "test-token"},
        )
        assert status_response.status_code == 200
        assert status_response.json()["parameters"]["source_ipv4"] == "192.0.2.8"


def test_device_detail_shows_attacker_ip_for_healing_action(tmp_path, monkeypatch):
    client, database = client_for(tmp_path, monkeypatch)
    with client:
        database.upsert_device("iot-1", "fingerprint", "camera", "10.42.0.2")
        database.create_healing_request(
            "request-1",
            "NET-03",
            "iot-1",
            {
                "source_ipv4": "192.0.2.8",
                "attacker_mac": "02:00:00:00:00:02",
                "ttl_seconds": 300,
            },
            source="cloud",
        )
        database.claim_healing_request()
        database.complete_healing_request(
            "request-1",
            "succeeded",
            result={"source_ipv4": "192.0.2.8", "blocked": True},
        )

        page = client.get("/devices/iot-1")

    assert page.status_code == 200
    assert "Attacker" in page.text
    assert "192.0.2.8" in page.text
    assert "02:00:00:00:00:02" in page.text
    assert "succeeded" in page.text


def test_post_healing_action_requires_token_and_supported_id(tmp_path, monkeypatch):
    client, database = client_for(tmp_path, monkeypatch)
    with client:
        database.upsert_device("iot-1", "fingerprint", "camera", "10.42.0.2")
        unauthorized = client.post(
            "/api/devices/iot-1/healing-actions/SEG-03",
            json={"parameters": {}},
        )
        assert unauthorized.status_code == 401

        unsupported = client.post(
            "/api/devices/iot-1/healing-actions/DEV-06",
            headers={"X-IoT-Guard-Token": "test-token"},
            json={"parameters": {}},
        )
        assert unsupported.status_code == 422
        assert unsupported.json()["detail"]["supported_action_ids"] == sorted(
            SUPPORTED_ACTIONS
        )


def test_dashboard_can_queue_device_unblock(tmp_path, monkeypatch):
    client, database = client_for(tmp_path, monkeypatch)
    with client:
        database.upsert_device(
            "iot-1",
            "fingerprint",
            "camera",
            "10.42.0.2",
            mac_address="02:00:00:00:00:01",
        )
        response = client.post(
            "/api/devices/iot-1/healing-actions/UNBLOCK",
            headers={"X-IoT-Guard-Token": "test-token"},
            json={"parameters": {"reason": "demonstration reset"}},
        )
        page = client.get("/devices/iot-1")

    assert response.status_code == 202
    assert response.json()["action_id"] == "UNBLOCK"
    assert "Healing actions" in page.text
    assert "Unblock device" in page.text
    assert "dashboard" in page.text


def test_dashboard_admin_panel_filters_and_queues_unblock(tmp_path, monkeypatch):
    client, database = client_for(tmp_path, monkeypatch)
    with client:
        database.upsert_device("iot-1", "fingerprint", "camera", "10.42.0.2")
        page = client.get("/")

    assert page.status_code == 200
    assert "Admin panel" in page.text
    assert "Find device" in page.text
    assert "Show hidden" in page.text
    assert "Reset database" in page.text
    assert "unblockDevice('iot-1')" in page.text
    assert 'fetch("/api/devices", {cache: "no-store"})' in page.text
    assert "window.setInterval(refreshDashboard, 5000)" in page.text
    assert '!document.querySelector(".admin-panel :focus")' not in page.text


def test_dashboard_shows_wireless_attack_alert(tmp_path, monkeypatch):
    client, database = client_for(tmp_path, monkeypatch)
    with client:
        database.log(
            "warning",
            "wireless",
            "Wireless attack detected: deauthentication_flood",
            {
                "attack_class": "deauthentication_flood",
                "source_mac": "02:00:00:00:00:09",
                "signal_dbm": -42,
            },
        )
        page = client.get("/")

    assert page.status_code == 200
    assert "Wireless security" in page.text
    assert "deauthentication flood" in page.text
    assert "02:00:00:00:00:09" in page.text
    assert "-42 dBm" in page.text


def test_admin_reset_database_requires_token_and_confirmation(tmp_path, monkeypatch):
    client, database = client_for(tmp_path, monkeypatch)
    with client:
        database.upsert_device("iot-1", "fingerprint", "camera", "10.42.0.2")
        unauthorized = client.post(
            "/api/admin/reset-database",
            json={"confirmation": "RESET"},
        )
        unconfirmed = client.post(
            "/api/admin/reset-database",
            headers={"X-IoT-Guard-Token": "test-token"},
            json={"confirmation": "reset"},
        )
        response = client.post(
            "/api/admin/reset-database",
            headers={"X-IoT-Guard-Token": "test-token"},
            json={"confirmation": "RESET"},
        )
        devices = client.get("/api/devices")

    assert unauthorized.status_code == 401
    assert unconfirmed.status_code == 422
    assert response.status_code == 200
    assert response.json()["deleted"]["devices"] == 1
    assert devices.json()["devices"] == []


def test_dashboard_lists_cloud_api_deliveries(tmp_path, monkeypatch):
    client, database = client_for(tmp_path, monkeypatch)
    with client:
        database.record_cloud_delivery(
            {
                "flag": "anomaly",
                "device_id": "iot-1",
                "endpoint": "https://cloud.example/report",
                "status": "accepted",
                "duration_ms": 42.5,
                "error": None,
                "payload": {"flag": "anomaly", "device_id": "iot-1"},
                "response": {"accepted": True},
            }
        )
        database.record_cloud_delivery(
            {
                "flag": "healing_active",
                "device_id": "iot-1",
                "endpoint": "https://cloud.example/report",
                "status": "failed",
                "duration_ms": 15.0,
                "error": "connection refused",
                "payload": {"flag": "healing_active", "action_id": "NET-05"},
                "response": None,
            }
        )
        page = client.get("/")
        api = client.get("/api/cloud-deliveries")
        dashboard = client.get("/api/devices")

    assert page.status_code == 200
    assert "Cloud API requests" in page.text
    assert "healing_active" in page.text.replace("_", "_")
    assert "connection refused" in page.text
    payload = api.json()["deliveries"]
    assert [item["status"] for item in payload] == ["failed", "accepted"]
    assert payload[0]["error"] == "connection refused"
    assert payload[1]["response"] == {"accepted": True}
    assert len(dashboard.json()["cloud_deliveries"]) == 2


def test_cloud_deliveries_endpoint_validates_limit(tmp_path, monkeypatch):
    client, _ = client_for(tmp_path, monkeypatch)
    with client:
        too_large = client.get("/api/cloud-deliveries?limit=1000")
        too_small = client.get("/api/cloud-deliveries?limit=0")
    assert too_large.status_code == 422
    assert too_small.status_code == 422