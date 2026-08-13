from __future__ import annotations

import ipaddress
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .database import Database


@dataclass(frozen=True)
class HealingAction:
    action_id: str
    name: str


SUPPORTED_ACTIONS = {
    "NET-03": HealingAction("NET-03", "Temporary source block"),
    "SEG-03": HealingAction("SEG-03", "Full isolation"),
}


class HealingActionError(RuntimeError):
    pass


class NftablesHealingExecutor:
    def __init__(
        self,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> None:
        self.runner = runner

    def execute(self, request: dict[str, Any]) -> dict[str, Any]:
        device_ipv4 = self._ipv4(request.get("ipv4"), "Device has no valid leased IPv4 address")
        if not request.get("connected"):
            raise HealingActionError("Device is not currently connected")
        self._ensure_ruleset()
        if request["action_id"] == "NET-03":
            return self._temporary_source_block(request["parameters"])
        if request["action_id"] == "SEG-03":
            return self._full_isolation(device_ipv4, request["parameters"])
        raise HealingActionError(f"Healing action {request['action_id']} is not implemented")

    def _temporary_source_block(self, parameters: dict[str, Any]) -> dict[str, Any]:
        source = self._ipv4(
            parameters.get("source_ipv4"), "NET-03 requires a valid source_ipv4 parameter"
        )
        try:
            ttl_seconds = int(parameters.get("ttl_seconds", 300))
        except (TypeError, ValueError) as exc:
            raise HealingActionError("ttl_seconds must be an integer") from exc
        if not 60 <= ttl_seconds <= 3600:
            raise HealingActionError("ttl_seconds must be between 60 and 3600")
        self._run(
            [
                "nft",
                "add",
                "element",
                "inet",
                "iot_guard",
                "blocked_sources",
                f"{{ {source} timeout {ttl_seconds}s }}",
            ]
        )
        return {"source_ipv4": source, "ttl_seconds": ttl_seconds, "blocked": True}

    def _full_isolation(self, device_ipv4: str, parameters: dict[str, Any]) -> dict[str, Any]:
        heartbeat = parameters.get("heartbeat_ipv4")
        if heartbeat is not None:
            heartbeat = self._ipv4(heartbeat, "heartbeat_ipv4 must be a valid IPv4 address")
            self._run(
                [
                    "nft", "insert", "rule", "inet", "iot_guard", "forward",
                    "ip", "saddr", device_ipv4, "ip", "daddr", heartbeat, "accept",
                ]
            )
            self._run(
                [
                    "nft", "insert", "rule", "inet", "iot_guard", "forward",
                    "ip", "saddr", heartbeat, "ip", "daddr", device_ipv4, "accept",
                ]
            )
        self._run(
            [
                "nft", "add", "element", "inet", "iot_guard", "isolated_devices",
                f"{{ {device_ipv4} }}",
            ]
        )
        return {
            "device_ipv4": device_ipv4,
            "heartbeat_ipv4": heartbeat,
            "isolated": True,
        }

    def _ensure_ruleset(self) -> None:
        result = self.runner(
            ["nft", "list", "table", "inet", "iot_guard"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            return
        ruleset = """table inet iot_guard {
    set blocked_sources {
        type ipv4_addr
        flags timeout
    }
    set isolated_devices {
        type ipv4_addr
    }
    chain forward {
        type filter hook forward priority -10; policy accept;
        ip saddr @blocked_sources counter drop
        ip saddr @isolated_devices counter drop
        ip daddr @isolated_devices counter drop
    }
}
"""
        self._run(["nft", "-f", "-"], input_text=ruleset)

    def _run(self, command: list[str], input_text: str | None = None) -> None:
        try:
            self.runner(
                command,
                input=input_text,
                capture_output=True,
                text=True,
                check=True,
            )
        except FileNotFoundError as exc:
            raise HealingActionError("nft executable is not installed") from exc
        except subprocess.CalledProcessError as exc:
            detail = (exc.stderr or exc.stdout or str(exc)).strip()
            raise HealingActionError(f"nftables command failed: {detail}") from exc

    @staticmethod
    def _ipv4(value: Any, message: str) -> str:
        try:
            return str(ipaddress.IPv4Address(value))
        except (ipaddress.AddressValueError, TypeError) as exc:
            raise HealingActionError(message) from exc


class HealingWorker:
    def __init__(self, database: Database, executor: NftablesHealingExecutor) -> None:
        self.database = database
        self.executor = executor

    def process_one(self) -> bool:
        request = self.database.claim_healing_request()
        if request is None:
            return False
        try:
            result = self.executor.execute(request)
        except HealingActionError as exc:
            self.database.complete_healing_request(
                request["request_id"], "failed", error=str(exc)
            )
        else:
            self.database.complete_healing_request(
                request["request_id"], "succeeded", result=result
            )
        return True
