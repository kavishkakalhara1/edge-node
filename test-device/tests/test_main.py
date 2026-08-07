import json

import pytest

from iot_test_device.main import PROFILES, Sensor, Settings


def test_sensor_payload_has_requested_size_and_sequence():
    sensor = Sensor("test-pi", seed=7)

    first = json.loads(sensor.sample(180))
    second = json.loads(sensor.sample(180))

    assert first["device"] == "test-pi"
    assert first["sequence"] == 1
    assert second["sequence"] == 2


def test_sensor_caps_large_payload():
    assert len(Sensor("test-pi", seed=7).sample(900)) == 900


def test_settings_reject_unknown_profile(monkeypatch):
    monkeypatch.setenv("IOT_TEST_PROFILE", "unknown")

    with pytest.raises(ValueError, match="Unknown profile"):
        Settings.from_env()


def test_burst_profile_is_more_active_than_normal():
    assert PROFILES["burst"].interval_seconds < PROFILES["normal"].interval_seconds
    assert PROFILES["burst"].packets_per_interval > PROFILES["normal"].packets_per_interval
