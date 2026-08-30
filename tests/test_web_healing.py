from dataclasses import replace

from fastapi.testclient import TestClient

from iot_guard import web
from iot_guard.database import Database
from iot_guard.healing import SUPPORTED_ACTIONS


def client_for(tmp_path, monkeypatch):
    database = Database(tmp_path / "guard.db")
    monkeypatch.setattr(web, "database", database)
    monkeypatch.setattr(web, "settings", replace(web.settings, healing_api_token="test-token"))
    return TestClient(web.app), database


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


def test_device_detail_returns_monitored_traffic(tmp_path, monkeypatch):
    client, database = client_for(tmp_path, monkeypatch)
    with client:
        database.upsert_device("iot-1", "fingerprint", "camera", "10.42.0.2")
        database.record_window(
            "iot-1",
            "2026-08-29T20:00:00+00:00",
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