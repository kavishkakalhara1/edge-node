from iot_guard.identity import DeviceIdentity, normalize_mac
from iot_guard.leases import LeaseRegistry, parse_station_macs


def test_device_ids_use_normalized_mac_without_colons():
    identity = DeviceIdentity(b"x" * 32)
    first = identity.device_id("AA-BB-CC-DD-EE-FF")
    assert first == identity.device_id("aa:bb:cc:dd:ee:ff")
    assert first == "id-aabbccddeeff"


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


def test_unreadable_lease_file_is_treated_as_empty(tmp_path, monkeypatch):
    lease_file = tmp_path / "leases"
    registry = LeaseRegistry(lease_file, DeviceIdentity(b"x" * 32))

    def deny_read(*args, **kwargs):
        raise PermissionError

    monkeypatch.setattr(type(lease_file), "read_text", deny_read)
    assert registry.refresh() == []
    assert registry.by_mac == {}


def test_station_dump_parser_returns_normalized_macs():
    output = """Station 02:00:00:00:00:01 (on wlan1)
	inactive time:\t10 ms
Station invalid (on wlan1)
Station 02:00:00:00:00:02 (on wlan1)
"""
    assert parse_station_macs(output) == {
        "02:00:00:00:00:01",
        "02:00:00:00:00:02",
    }
