from iot_guard.identity import DeviceIdentity, normalize_mac
from iot_guard.leases import LeaseRegistry


def test_device_ids_are_stable_and_do_not_expose_mac():
    identity = DeviceIdentity(b"x" * 32)
    first = identity.device_id("AA-BB-CC-DD-EE-FF")
    assert first == identity.device_id("aa:bb:cc:dd:ee:ff")
    assert "aa" not in first
    assert first.startswith("iot-")


def test_normalize_mac_rejects_invalid_values():
    try:
        normalize_mac("not-a-mac")
    except ValueError:
        pass
    else:
        raise AssertionError("Invalid MAC was accepted")


def test_client_to_client_traffic_resolves_both_leases(tmp_path):
    lease_file = tmp_path / "leases"
    lease_file.write_text(
        "2000000000 02:00:00:00:00:01 10.42.0.2 camera *\n"
        "2000000000 02:00:00:00:00:02 10.42.0.3 plug *\n"
    )
    registry = LeaseRegistry(lease_file, DeviceIdentity(b"x" * 32))
    registry.refresh()
    resolved = registry.resolve_all("02:00:00:00:00:01", "02:00:00:00:00:02")
    assert len(resolved) == 2
