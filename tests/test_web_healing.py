from dataclasses import replace

from fastapi.testclient import TestClient

from iot_guard import web
from iot_guard.database import Database


def client_for(tmp_path, monkeypatch):
    database = Database(tmp_path / "guard.db")
    monkeypatch.setattr(web, "database", database)
    monkeypatch.setattr(web, "settings", replace(web.settings, healing_api_token="test-token"))
    return TestClient(web.app), database


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
        assert unsupported.json()["detail"]["supported_action_ids"] == ["NET-03", "SEG-03"]