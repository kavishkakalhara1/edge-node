import subprocess

import pytest

from iot_guard.database import Database
from iot_guard.healing import HealingActionError, HealingWorker, NftablesHealingExecutor


class NftRunner:
    def __init__(self):
        self.commands = []

    def __call__(self, command, **kwargs):
        self.commands.append((command, kwargs.get("input")))
        if command[:3] == ["nft", "list", "table"]:
            return subprocess.CompletedProcess(command, 1, "", "table missing")
        return subprocess.CompletedProcess(command, 0, "", "")


def test_healing_request_is_claimed_and_completed_once(tmp_path):
    database = Database(tmp_path / "guard.db")
    database.initialize()
    database.upsert_device("iot-1", "fingerprint", "camera", "10.42.0.2")
    database.create_healing_request(
        "request-1", "SEG-03", "iot-1", {"reason": "critical risk"}
    )

    runner = NftRunner()
    worker = HealingWorker(database, NftablesHealingExecutor(runner))
    assert worker.process_one() is True
    assert worker.process_one() is False

    completed = database.healing_request("request-1")
    assert completed["status"] == "succeeded"
    assert completed["result"]["device_ipv4"] == "10.42.0.2"
    assert any("isolated_devices" in command for command, _input in runner.commands)


def test_temporary_source_block_validates_and_applies_ttl():
    runner = NftRunner()
    executor = NftablesHealingExecutor(runner)
    result = executor.execute(
        {
            "action_id": "NET-03",
            "ipv4": "10.42.0.2",
            "connected": 1,
            "parameters": {"source_ipv4": "192.0.2.8", "ttl_seconds": 900},
        }
    )
    assert result == {"source_ipv4": "192.0.2.8", "ttl_seconds": 900, "blocked": True}
    assert any("900s" in command[-1] for command, _input in runner.commands)


def test_temporary_source_block_rejects_invalid_source():
    executor = NftablesHealingExecutor(NftRunner())
    with pytest.raises(HealingActionError, match="source_ipv4"):
        executor.execute(
            {
                "action_id": "NET-03",
                "ipv4": "10.42.0.2",
                "connected": 1,
                "parameters": {"source_ipv4": "not-an-address"},
            }
        )