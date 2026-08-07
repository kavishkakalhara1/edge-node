from iot_guard.collector import RollingWindowBuffer


def add(buffer, device, interval, session, timestamp):
    return buffer.add(device, interval, session, timestamp, {"value": timestamp})


def test_buffer_waits_for_complete_window():
    buffer = RollingWindowBuffer(4, 120)
    assert add(buffer, "a", 2, "session", 0) is None
    assert add(buffer, "a", 2, "session", 2) is None
    assert add(buffer, "a", 2, "session", 4) is None
    window = add(buffer, "a", 2, "session", 6)
    assert [row["value"] for row in window] == [0, 2, 4, 6]


def test_buffers_do_not_cross_devices_intervals_or_sessions():
    buffer = RollingWindowBuffer(2, 120)
    assert add(buffer, "a", 2, "one", 0) is None
    assert add(buffer, "b", 2, "one", 2) is None
    assert add(buffer, "a", 10, "one", 10) is None
    assert add(buffer, "a", 2, "two", 2) is None
    assert add(buffer, "a", 2, "one", 2) is not None


def test_nonconsecutive_and_stale_records_reset_buffers():
    buffer = RollingWindowBuffer(2, 5)
    assert add(buffer, "a", 2, "session", 0) is None
    assert add(buffer, "a", 2, "session", 8) is None
    buffer.clear_stale(14)
    assert not buffer.buffers
