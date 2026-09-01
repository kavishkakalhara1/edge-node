import json
import subprocess
from pathlib import Path

import pytest

from iot_guard.database import Database
from iot_guard.healing import (
    CLOUD_ACTIONS,
    SUPPORTED_ACTIONS,
    HealingActionError,
    HealingWorker,
    NftablesHealingExecutor,
)


class NftRunner:
    def __init__(self):
        self.commands = []

    def __call__(self, command, **kwargs):
        self.commands.append((command, kwargs.get("input")))
        if command[:3] == ["nft", "list", "table"]:
            return subprocess.CompletedProcess(command, 1, "", "table missing")
        return subprocess.CompletedProcess(command, 0, "", "")


def test_healing_catalog_matches_executor_registries():
    catalog_path = Path(__file__).parents[1] / "docs" / "healing-actions.json"
    actions = json.loads(catalog_path.read_text())["actions"]
    action_ids = [action["action_id"] for action in actions]
    implemented = {
        action["action_id"]
        for action in actions
        if action["pi_feasibility"] == "implemented"
    }
    automatic = {action["action_id"] for action in actions if action["automatic"]}

    assert len(action_ids) == len(set(action_ids))
    assert implemented == SUPPORTED_ACTIONS.keys() - {"UNBLOCK"}
    assert automatic == CLOUD_ACTIONS.keys()


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


def test_cloud_style_source_block_defaults_to_device_ipv4():
    runner = NftRunner()
    result = NftablesHealingExecutor(runner).execute(
        {
            "action_id": "NET-03",
            "ipv4": "10.42.0.2",
            "connected": 1,
            "parameters": {},
        }
    )

    assert result["source_ipv4"] == "10.42.0.2"
    assert result["ttl_seconds"] == 300


def test_protected_device_is_allowed_before_drop_rules_and_cannot_be_targeted():
    runner = NftRunner()
    executor = NftablesHealingExecutor(
        runner,
        protected_macs=("38:2c:e5:1d:02:fb",),
    )

    with pytest.raises(HealingActionError, match="protected device"):
        executor.execute(
            {
                "action_id": "SEG-03",
                "ipv4": "192.168.50.112",
                "mac_address": "38:2c:e5:1d:02:fb",
                "connected": 1,
                "parameters": {},
            }
        )

    executor.execute(request("SEG-03"))
    ruleset = next(
        input_text
        for command, input_text in runner.commands
        if command == ["nft", "-f", "-"]
    )
    assert "elements = { 38:2c:e5:1d:02:fb }" in ruleset
    assert ruleset.index("ether saddr @protected_devices") < ruleset.index(
        "ip saddr @blocked_sources"
    )


def test_existing_ruleset_inserts_protected_device_exemption():
    runner = NftRunner()

    def existing_table(command, **kwargs):
        runner.commands.append((command, kwargs.get("input")))
        if command[:3] == ["nft", "list", "table"]:
            return subprocess.CompletedProcess(
                command,
                0,
                "table inet iot_guard { chain forward { ip saddr @blocked_sources drop } }",
                "",
            )
        return subprocess.CompletedProcess(command, 0, "", "")

    executor = NftablesHealingExecutor(
        existing_table,
        protected_macs=("38:2c:e5:1d:02:fb",),
    )
    executor.prepare()

    commands = [command for command, _input in runner.commands]
    assert any(command[:4] == ["nft", "add", "set", "inet"] for command in commands)
    assert any(
        command[:4] == ["nft", "add", "element", "inet"]
        and "38:2c:e5:1d:02:fb" in command[-1]
        for command in commands
    )
    assert any(
        command[:4] == ["nft", "insert", "rule", "inet"]
        and "@protected_devices" in command
        for command in commands
    )


def test_mac_block_and_unblock_are_device_scoped():
    runner = NftRunner()
    executor = NftablesHealingExecutor(runner)
    blocked = executor.execute(
        {
            "action_id": "SEG-02",
            "ipv4": "10.42.0.2",
            "mac_address": "02:00:00:00:00:01",
            "connected": 1,
            "parameters": {},
        }
    )
    unblocked = executor.execute(
        {
            "action_id": "UNBLOCK",
            "ipv4": "10.42.0.2",
            "mac_address": "02:00:00:00:00:01",
            "connected": 0,
            "parameters": {},
        }
    )

    assert blocked == {"mac_address": "02:00:00:00:00:01", "blocked": True}
    assert unblocked["unblocked"] is True
    delete_commands = [command for command, _input in runner.commands if "delete" in command]
    assert len(delete_commands) == 8
    assert any("blocked_devices" in command for command in delete_commands)
    assert sum(command[0] == "tc" for command in delete_commands) == 2


def request(action_id, parameters=None):
    return {
        "action_id": action_id,
        "device_id": "iot-1",
        "ipv4": "10.42.0.2",
        "mac_address": "02:00:00:00:00:01",
        "connected": 1,
        "parameters": parameters or {},
    }


@pytest.mark.parametrize("action_id,rate", [("NET-01", 1024), ("NET-08", 512)])
def test_rate_controls_apply_bidirectional_tc_policing(action_id, rate):
    runner = NftRunner()
    result = NftablesHealingExecutor(runner).execute(request(action_id))

    assert result["rate_kbit"] == rate
    filters = [command for command, _input in runner.commands if command[:2] == ["tc", "filter"]]
    assert len(filters) == 2
    assert any("src_ip" in command for command in filters)
    assert any("dst_ip" in command for command in filters)


def test_rate_controls_pass_protected_source_mac_before_policing():
    runner = NftRunner()
    executor = NftablesHealingExecutor(
        runner,
        protected_macs=("38:2c:e5:1d:02:fb",),
    )

    executor.execute(request("NET-01"))

    filters = [command for command, _input in runner.commands if command[:2] == ["tc", "filter"]]
    protected_filters = [command for command in filters if "src_mac" in command]
    assert len(protected_filters) == 2
    assert all("38:2c:e5:1d:02:fb" in command for command in protected_filters)
    assert all(command[command.index("pref") + 1] == "1" for command in protected_filters)


@pytest.mark.parametrize(
    "action_id,set_name,parameters",
    [
        ("NET-02", "flood_hardened", {}),
        ("NET-05", "scan_filtered", {}),
        ("ACC-01", "progressive_bans", {"level": 3}),
    ],
)
def test_timed_network_controls(action_id, set_name, parameters):
    runner = NftRunner()
    result = NftablesHealingExecutor(runner).execute(request(action_id, parameters))

    assert result["hardened"] is True
    assert any(set_name in command for command, _input in runner.commands)


def test_parameterized_network_filters():
    runner = NftRunner()
    executor = NftablesHealingExecutor(runner)

    port = executor.execute(request("NET-04", {"protocol": "tcp", "port": 443}))
    c2 = executor.execute(request("NET-06", {"destination_ipv4": "192.0.2.8"}))
    aggregate = executor.execute(request("NET-07", {"source_cidr": "198.51.100.7/24"}))

    assert port["port"] == 443
    assert c2["destination_ipv4"] == "192.0.2.8"
    assert aggregate["source_cidr"] == "198.51.100.0/24"
    assert any("blocked_tcp_ports" in command for command, _input in runner.commands)
    assert any("blocked_destinations" in command for command, _input in runner.commands)
    assert any("blocked_networks" in command for command, _input in runner.commands)


@pytest.mark.parametrize("action_id", ["L2-01", "L2-02"])
def test_l2_actions_pin_trusted_dhcp_binding(action_id):
    runner = NftRunner()
    result = NftablesHealingExecutor(runner).execute(request(action_id))

    assert result["binding"] == "permanent"
    assert any(command[:3] == ["ip", "neighbor", "replace"] for command, _input in runner.commands)


def test_escalation_actions_and_permanent_quarantine_approval():
    executor = NftablesHealingExecutor(NftRunner())
    assert executor.execute(request("ESC-01"))["notified"] is True
    assert executor.execute(request("ESC-03"))["report_generated"] is True
    with pytest.raises(HealingActionError, match="approved=true"):
        executor.execute(request("ESC-02"))
    assert executor.execute(request("ESC-02", {"approved": True}))["permanent"] is True


def test_incident_report_worker_stores_database_snapshot(tmp_path):
    database = Database(tmp_path / "guard.db")
    database.initialize()
    database.upsert_device("iot-1", "fingerprint", "camera", "10.42.0.2")
    database.create_healing_request("report-1", "ESC-03", "iot-1", {})

    worker = HealingWorker(database, NftablesHealingExecutor(NftRunner()))
    assert worker.process_one() is True

    result = database.healing_request("report-1")["result"]
    assert result["report_generated"] is True
    assert result["snapshot"]["device"]["device_id"] == "iot-1"
    assert result["snapshot"]["traffic"]["window_count"] == 0