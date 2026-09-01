from __future__ import annotations

import ipaddress
import logging
import re
import subprocess
import zlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .database import Database
from .identity import normalize_mac

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class HealingAction:
    action_id: str
    name: str
    reversible: bool = False


CLOUD_ACTIONS = {
    "NET-01": HealingAction("NET-01", "Adaptive rate limiting", True),
    "NET-02": HealingAction("NET-02", "Flood-specific hardening", True),
    "NET-03": HealingAction("NET-03", "Temporary source block", True),
    "NET-05": HealingAction("NET-05", "Probe/scan filtering", True),
    "NET-08": HealingAction("NET-08", "Traffic shaping", True),
    "SEG-02": HealingAction("SEG-02", "MAC-level block", True),
    "SEG-03": HealingAction("SEG-03", "Full isolation", True),
    "L2-01": HealingAction("L2-01", "ARP truth restoration", True),
    "L2-02": HealingAction("L2-02", "ARP/DHCP inspection", True),
    "ACC-01": HealingAction("ACC-01", "Progressive source ban", True),
    "ESC-01": HealingAction("ESC-01", "Operator notification"),
    "ESC-03": HealingAction("ESC-03", "Incident report"),
}
PARAMETERIZED_ACTIONS = {
    "NET-04": HealingAction("NET-04", "Port/protocol block", True),
    "NET-06": HealingAction("NET-06", "Egress and C2 blocking", True),
    "NET-07": HealingAction("NET-07", "Aggregate source block", True),
    "ESC-02": HealingAction("ESC-02", "Permanent quarantine", True),
}
INTERNAL_ACTIONS = {"UNBLOCK": HealingAction("UNBLOCK", "Remove device controls")}
SUPPORTED_ACTIONS = {**CLOUD_ACTIONS, **PARAMETERIZED_ACTIONS, **INTERNAL_ACTIONS}


class HealingActionError(RuntimeError):
    pass


class NftablesHealingExecutor:
    def __init__(
        self,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
        hotspot_interface: str = "wlan1",
        protected_macs: tuple[str, ...] = (),
    ) -> None:
        self.runner = runner
        self.hotspot_interface = hotspot_interface
        self.protected_macs = tuple(self._mac(mac) for mac in protected_macs)

    def prepare(self) -> None:
        self._ensure_ruleset()

    def execute(self, request: dict[str, Any]) -> dict[str, Any]:
        if request["action_id"] == "UNBLOCK":
            return self._unblock(request.get("ipv4"), request.get("mac_address"))
        if self._is_protected(request.get("mac_address")):
            raise HealingActionError("Healing actions cannot target a protected device")
        device_ipv4 = self._ipv4(request.get("ipv4"), "Device has no valid leased IPv4 address")
        if not request.get("connected"):
            raise HealingActionError("Device is not currently connected")
        self._ensure_ruleset()
        if request["action_id"] == "NET-01":
            return self._rate_limit(device_ipv4, request["parameters"], adaptive=True)
        if request["action_id"] == "NET-02":
            return self._timed_set("flood_hardened", device_ipv4, request["parameters"], 120)
        if request["action_id"] == "NET-03":
            return self._temporary_source_block(device_ipv4, request["parameters"])
        if request["action_id"] == "NET-04":
            return self._port_block(device_ipv4, request["parameters"])
        if request["action_id"] == "NET-05":
            result = self._timed_set(
                "scan_filtered", device_ipv4, request["parameters"], 300
            )
            return result | {"filtered": True}
        if request["action_id"] == "NET-06":
            return self._egress_block(device_ipv4, request["parameters"])
        if request["action_id"] == "NET-07":
            return self._aggregate_block(request["parameters"])
        if request["action_id"] == "NET-08":
            return self._rate_limit(device_ipv4, request["parameters"], adaptive=False)
        if request["action_id"] == "SEG-02":
            return self._mac_block(request.get("mac_address"))
        if request["action_id"] == "SEG-03":
            return self._full_isolation(device_ipv4, request["parameters"])
        if request["action_id"] in {"L2-01", "L2-02"}:
            return self._restore_neighbor(device_ipv4, request.get("mac_address"))
        if request["action_id"] == "ACC-01":
            return self._progressive_ban(device_ipv4, request["parameters"])
        if request["action_id"] == "ESC-01":
            LOGGER.warning("Operator notification requested for device=%s", request["device_id"])
            return {"notified": True, "channel": "journal"}
        if request["action_id"] == "ESC-02":
            if request["parameters"].get("approved") is not True:
                raise HealingActionError("ESC-02 requires approved=true")
            return self._full_isolation(device_ipv4, {}) | {"permanent": True}
        if request["action_id"] == "ESC-03":
            return {
                "report_generated": True,
                "device_id": request["device_id"],
                "device_ipv4": device_ipv4,
                "source": request.get("source", "unknown"),
            }
        raise HealingActionError(f"Healing action {request['action_id']} is not implemented")

    def _rate_limit(
        self, device_ipv4: str, parameters: dict[str, Any], *, adaptive: bool
    ) -> dict[str, Any]:
        default_rate = 1024 if adaptive else 512
        try:
            rate_kbit = int(parameters.get("rate_kbit", default_rate))
            burst_kb = int(parameters.get("burst_kb", 64))
        except (TypeError, ValueError) as exc:
            raise HealingActionError("rate_kbit and burst_kb must be integers") from exc
        if not 64 <= rate_kbit <= 100_000 or not 8 <= burst_kb <= 4096:
            raise HealingActionError("rate_kbit or burst_kb is outside the safe range")
        preference = self._tc_preference(device_ipv4)
        self._run(["tc", "qdisc", "replace", "dev", self.hotspot_interface, "clsact"])
        for protected_preference, mac_address in enumerate(self.protected_macs, start=1):
            for direction in ("ingress", "egress"):
                self._run(
                    [
                        "tc", "filter", "replace", "dev", self.hotspot_interface,
                        direction, "protocol", "ip", "pref", str(protected_preference),
                        "flower", "src_mac", mac_address, "action", "pass",
                    ]
                )
        for direction, address_field in (("ingress", "src_ip"), ("egress", "dst_ip")):
            self._run(
                [
                    "tc", "filter", "replace", "dev", self.hotspot_interface, direction,
                    "protocol", "ip", "pref", str(preference), "flower", address_field,
                    device_ipv4, "action", "police", "rate", f"{rate_kbit}kbit",
                    "burst", f"{burst_kb}kb", "drop",
                ]
            )
        return {
            "device_ipv4": device_ipv4,
            "rate_kbit": rate_kbit,
            "burst_kb": burst_kb,
            "interface": self.hotspot_interface,
            "limited": True,
        }

    def _timed_set(
        self, set_name: str, device_ipv4: str, parameters: dict[str, Any], default_ttl: int
    ) -> dict[str, Any]:
        try:
            ttl_seconds = int(parameters.get("ttl_seconds", default_ttl))
        except (TypeError, ValueError) as exc:
            raise HealingActionError("ttl_seconds must be an integer") from exc
        if not 60 <= ttl_seconds <= 86400:
            raise HealingActionError("ttl_seconds must be between 60 and 86400")
        self._run(
            ["nft", "add", "element", "inet", "iot_guard", set_name,
             f"{{ {device_ipv4} timeout {ttl_seconds}s }}"],
            ignore_existing=True,
        )
        return {"device_ipv4": device_ipv4, "ttl_seconds": ttl_seconds, "hardened": True}

    def _port_block(self, device_ipv4: str, parameters: dict[str, Any]) -> dict[str, Any]:
        protocol = str(parameters.get("protocol", "tcp")).lower()
        if protocol not in {"tcp", "udp"}:
            raise HealingActionError("protocol must be tcp or udp")
        try:
            port = int(parameters["port"])
        except (KeyError, TypeError, ValueError) as exc:
            raise HealingActionError("NET-04 requires a valid port") from exc
        if not 1 <= port <= 65535:
            raise HealingActionError("port must be between 1 and 65535")
        self._run(
            ["nft", "add", "element", "inet", "iot_guard", f"blocked_{protocol}_ports",
             f"{{ {device_ipv4} . {port} }}"],
            ignore_existing=True,
        )
        return {"device_ipv4": device_ipv4, "protocol": protocol, "port": port, "blocked": True}

    def _egress_block(self, device_ipv4: str, parameters: dict[str, Any]) -> dict[str, Any]:
        destination = self._ipv4(
            parameters.get("destination_ipv4"),
            "NET-06 requires a valid destination_ipv4",
        )
        self._run(
            ["nft", "add", "element", "inet", "iot_guard", "blocked_destinations",
             f"{{ {device_ipv4} . {destination} }}"],
            ignore_existing=True,
        )
        return {"device_ipv4": device_ipv4, "destination_ipv4": destination, "blocked": True}

    def _aggregate_block(self, parameters: dict[str, Any]) -> dict[str, Any]:
        try:
            network = str(ipaddress.IPv4Network(parameters.get("source_cidr"), strict=False))
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, TypeError) as exc:
            raise HealingActionError("NET-07 requires a valid source_cidr") from exc
        self._run(
            ["nft", "add", "element", "inet", "iot_guard", "blocked_networks",
             f"{{ {network} }}"],
            ignore_existing=True,
        )
        return {"source_cidr": network, "blocked": True}

    def _restore_neighbor(self, device_ipv4: str, mac_address: Any) -> dict[str, Any]:
        normalized_mac = self._mac(mac_address)
        self._run(
            ["ip", "neighbor", "replace", device_ipv4, "lladdr", normalized_mac,
             "nud", "permanent", "dev", self.hotspot_interface]
        )
        return {"device_ipv4": device_ipv4, "mac_address": normalized_mac, "binding": "permanent"}

    def _progressive_ban(self, device_ipv4: str, parameters: dict[str, Any]) -> dict[str, Any]:
        try:
            level = int(parameters.get("level", 1))
        except (TypeError, ValueError) as exc:
            raise HealingActionError("level must be an integer") from exc
        if not 1 <= level <= 5:
            raise HealingActionError("level must be between 1 and 5")
        ttl_seconds = (60, 300, 900, 3600, 86400)[level - 1]
        result = self._timed_set("progressive_bans", device_ipv4, {"ttl_seconds": ttl_seconds}, ttl_seconds)
        return result | {"level": level}

    def _temporary_source_block(
        self, device_ipv4: str, parameters: dict[str, Any]
    ) -> dict[str, Any]:
        source = self._ipv4(
            parameters.get("source_ipv4", device_ipv4),
            "NET-03 requires a valid source_ipv4 parameter",
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
            ],
            ignore_existing=True,
        )
        return {"source_ipv4": source, "ttl_seconds": ttl_seconds, "blocked": True}

    def _mac_block(self, mac_address: Any) -> dict[str, Any]:
        normalized_mac = self._mac(mac_address)
        self._run(
            [
                "nft", "add", "element", "inet", "iot_guard", "blocked_devices",
                f"{{ {normalized_mac} }}",
            ],
            ignore_existing=True,
        )
        return {"mac_address": normalized_mac, "blocked": True}

    def _unblock(self, ipv4: Any, mac_address: Any) -> dict[str, Any]:
        self._ensure_ruleset()
        removed = []
        try:
            device_ipv4 = self._ipv4(ipv4, "")
        except HealingActionError:
            device_ipv4 = None
        if device_ipv4:
            for set_name in (
                "blocked_sources", "isolated_devices", "flood_hardened",
                "scan_filtered", "progressive_bans",
            ):
                self._run(
                    ["nft", "delete", "element", "inet", "iot_guard", set_name,
                     f"{{ {device_ipv4} }}"],
                    ignore_missing=True,
                )
                removed.append(f"{set_name}:{device_ipv4}")
            preference = self._tc_preference(device_ipv4)
            for direction in ("ingress", "egress"):
                self._run(
                    ["tc", "filter", "delete", "dev", self.hotspot_interface,
                     direction, "pref", str(preference)],
                    ignore_missing=True,
                )
            removed.append(f"rate_limit:{device_ipv4}")
            for set_name in (
                "blocked_tcp_ports", "blocked_udp_ports", "blocked_destinations",
            ):
                removed.extend(self._remove_device_pairs(set_name, device_ipv4))
        if isinstance(mac_address, str) and len(mac_address.split(":")) == 6:
            normalized_mac = mac_address.lower()
            self._run(
                ["nft", "delete", "element", "inet", "iot_guard", "blocked_devices",
                 f"{{ {normalized_mac} }}"],
                ignore_missing=True,
            )
            removed.append(f"blocked_devices:{normalized_mac}")
        if device_ipv4:
            removed.extend(self._remove_matching_networks(device_ipv4))
        return {"unblocked": True, "removed": removed}

    def _remove_matching_networks(self, device_ipv4: str) -> list[str]:
        result = self.runner(
            ["nft", "list", "set", "inet", "iot_guard", "blocked_networks"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            return []
        try:
            address = ipaddress.IPv4Address(device_ipv4)
        except ValueError:
            return []
        removed: list[str] = []
        for candidate in re.findall(r"\d+\.\d+\.\d+\.\d+/\d+", result.stdout):
            try:
                network = ipaddress.IPv4Network(candidate, strict=False)
            except ValueError:
                continue
            if address in network:
                self._run(
                    ["nft", "delete", "element", "inet", "iot_guard", "blocked_networks",
                     f"{{ {candidate} }}"],
                    ignore_missing=True,
                )
                removed.append(f"blocked_networks:{candidate}")
        return removed

    def _remove_device_pairs(self, set_name: str, device_ipv4: str) -> list[str]:
        result = self.runner(
            ["nft", "list", "set", "inet", "iot_guard", set_name],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            return []
        values = re.findall(
            rf"{re.escape(device_ipv4)}\s+\.\s+([^,\s}}]+)", result.stdout
        )
        removed = []
        for value in values:
            self._run(
                ["nft", "delete", "element", "inet", "iot_guard", set_name,
                 f"{{ {device_ipv4} . {value} }}"],
                ignore_missing=True,
            )
            removed.append(f"{set_name}:{device_ipv4}.{value}")
        return removed

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
            ],
            ignore_existing=True,
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
            self._ensure_protected_devices(result.stdout)
            additions = {
                "blocked_devices": (
                    "{ type ether_addr; }",
                    (
                        ("ether", "saddr", "@blocked_devices", "counter", "drop"),
                        ("ether", "daddr", "@blocked_devices", "counter", "drop"),
                    ),
                ),
                "flood_hardened": (
                    "{ type ipv4_addr; flags timeout; }",
                    (("ip", "saddr", "@flood_hardened", "counter", "drop"),),
                ),
                "scan_filtered": (
                    "{ type ipv4_addr; flags timeout; }",
                    (),
                ),
                "progressive_bans": (
                    "{ type ipv4_addr; flags timeout; }",
                    (("ip", "saddr", "@progressive_bans", "counter", "drop"),),
                ),
                "blocked_tcp_ports": (
                    "{ type ipv4_addr . inet_service; }",
                    (("ip", "saddr", ".", "tcp", "dport", "@blocked_tcp_ports", "counter", "drop"),),
                ),
                "blocked_udp_ports": (
                    "{ type ipv4_addr . inet_service; }",
                    (("ip", "saddr", ".", "udp", "dport", "@blocked_udp_ports", "counter", "drop"),),
                ),
                "blocked_destinations": (
                    "{ type ipv4_addr . ipv4_addr; }",
                    (("ip", "saddr", ".", "ip", "daddr", "@blocked_destinations", "counter", "drop"),),
                ),
                "blocked_networks": (
                    "{ type ipv4_addr; flags interval; }",
                    (("ip", "saddr", "@blocked_networks", "counter", "drop"),),
                ),
            }
            for set_name, (definition, rules) in additions.items():
                if set_name in result.stdout:
                    continue
                self._run(
                    [
                        "nft", "add", "set", "inet", "iot_guard", set_name, definition,
                    ]
                )
                for rule in rules:
                    self._run([
                        "nft", "add", "rule", "inet", "iot_guard", "forward",
                        *rule,
                    ])
            self._ensure_scan_filter_rules()
            return
        protected_elements = ", ".join(self.protected_macs)
        protected_rule = (
            "        ether saddr @protected_devices counter accept\n"
            if self.protected_macs
            else ""
        )
        ruleset = """table inet iot_guard {
    set protected_devices {
        type ether_addr
        elements = { __PROTECTED_ELEMENTS__ }
    }
    set blocked_sources {
        type ipv4_addr
        flags timeout
    }
    set isolated_devices {
        type ipv4_addr
    }
    set blocked_devices {
        type ether_addr
    }
    set flood_hardened {
        type ipv4_addr
        flags timeout
    }
    set scan_filtered {
        type ipv4_addr
        flags timeout
    }
    set progressive_bans {
        type ipv4_addr
        flags timeout
    }
    set blocked_tcp_ports {
        type ipv4_addr . inet_service
    }
    set blocked_udp_ports {
        type ipv4_addr . inet_service
    }
    set blocked_destinations {
        type ipv4_addr . ipv4_addr
    }
    set blocked_networks {
        type ipv4_addr
        flags interval
    }
    chain forward {
        type filter hook forward priority -10; policy accept;
    __PROTECTED_RULE__        ip saddr @blocked_sources counter drop
        ip saddr @isolated_devices counter drop
        ip daddr @isolated_devices counter drop
        ether saddr @blocked_devices counter drop
        ether daddr @blocked_devices counter drop
        ip saddr @flood_hardened counter drop
        ip saddr @scan_filtered tcp flags & (fin|syn|rst|psh|ack|urg) == 0 counter drop comment "iot-guard-scan-null"
        ip saddr @scan_filtered tcp flags & (fin|syn|rst|psh|ack|urg) == fin counter drop comment "iot-guard-scan-fin"
        ip saddr @scan_filtered tcp flags & (fin|syn|rst|psh|ack|urg) == fin|psh|urg counter drop comment "iot-guard-scan-xmas"
        ip saddr @scan_filtered tcp flags syn ct state new limit rate over 20/second counter drop comment "iot-guard-scan-syn-rate"
        ip saddr @scan_filtered icmp type echo-request limit rate over 5/second counter drop comment "iot-guard-scan-icmp-rate"
        ip saddr @progressive_bans counter drop
        ip saddr . tcp dport @blocked_tcp_ports counter drop
        ip saddr . udp dport @blocked_udp_ports counter drop
        ip saddr . ip daddr @blocked_destinations counter drop
        ip saddr @blocked_networks counter drop
    }
}
        """
        ruleset = ruleset.replace("__PROTECTED_ELEMENTS__", protected_elements)
        ruleset = ruleset.replace("__PROTECTED_RULE__", protected_rule)
        self._run(["nft", "-f", "-"], input_text=ruleset)

    def _ensure_scan_filter_rules(self) -> None:
        result = self.runner(
            ["nft", "-a", "list", "chain", "inet", "iot_guard", "forward"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise HealingActionError("Unable to inspect nftables scan-filter rules")
        for line in result.stdout.splitlines():
            if (
                "ip saddr @scan_filtered" in line
                and 'comment "iot-guard-scan-' not in line
                and " drop" in line
            ):
                handle = re.search(r"# handle (\d+)", line)
                if handle is not None:
                    self._run(
                        [
                            "nft", "delete", "rule", "inet", "iot_guard", "forward",
                            "handle", handle.group(1),
                        ]
                    )
        rules = (
            (
                "tcp", "flags", "&", "(fin|syn|rst|psh|ack|urg)", "==", "0",
                "counter", "drop", "comment", "iot-guard-scan-null",
            ),
            (
                "tcp", "flags", "&", "(fin|syn|rst|psh|ack|urg)", "==", "fin",
                "counter", "drop", "comment", "iot-guard-scan-fin",
            ),
            (
                "tcp", "flags", "&", "(fin|syn|rst|psh|ack|urg)", "==",
                "fin|psh|urg", "counter", "drop", "comment", "iot-guard-scan-xmas",
            ),
            (
                "tcp", "flags", "syn", "ct", "state", "new", "limit", "rate",
                "over", "20/second", "counter", "drop", "comment",
                "iot-guard-scan-syn-rate",
            ),
            (
                "icmp", "type", "echo-request", "limit", "rate", "over", "5/second",
                "counter", "drop", "comment", "iot-guard-scan-icmp-rate",
            ),
        )
        for rule in rules:
            marker = rule[-1]
            if marker in result.stdout:
                continue
            self._run(
                [
                    "nft", "add", "rule", "inet", "iot_guard", "forward",
                    "ip", "saddr", "@scan_filtered", *rule,
                ]
            )

    def _ensure_protected_devices(self, ruleset: str) -> None:
        if "set protected_devices" not in ruleset:
            self._run(
                [
                    "nft", "add", "set", "inet", "iot_guard", "protected_devices",
                    "{ type ether_addr; }",
                ]
            )
        for mac_address in self.protected_macs:
            self._run(
                [
                    "nft", "add", "element", "inet", "iot_guard", "protected_devices",
                    f"{{ {mac_address} }}",
                ],
                ignore_existing=True,
            )
        if self.protected_macs and "ether saddr @protected_devices" not in ruleset:
            self._run(
                [
                    "nft", "insert", "rule", "inet", "iot_guard", "forward",
                    "ether", "saddr", "@protected_devices", "counter", "accept",
                ]
            )

    def _run(
        self,
        command: list[str],
        input_text: str | None = None,
        *,
        ignore_existing: bool = False,
        ignore_missing: bool = False,
    ) -> None:
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
            if ignore_existing and "File exists" in detail:
                return
            if ignore_missing and any(
                text in detail
                for text in (
                    "No such file", "No such element", "Cannot find device",
                    "Parent Qdisc doesn't exists", "Invalid argument",
                )
            ):
                return
            raise HealingActionError(f"nftables command failed: {detail}") from exc

    @staticmethod
    def _ipv4(value: Any, message: str) -> str:
        try:
            return str(ipaddress.IPv4Address(value))
        except (ipaddress.AddressValueError, TypeError) as exc:
            raise HealingActionError(message) from exc

    @staticmethod
    def _mac(value: Any) -> str:
        try:
            return normalize_mac(value)
        except (TypeError, ValueError) as exc:
            raise HealingActionError("Device has no valid MAC address") from exc

    def _is_protected(self, value: Any) -> bool:
        if not isinstance(value, str):
            return False
        try:
            return self._mac(value) in self.protected_macs
        except HealingActionError:
            return False

    @staticmethod
    def _tc_preference(device_ipv4: str) -> int:
        return 1000 + zlib.crc32(device_ipv4.encode("ascii")) % 60000


class HealingWorker:
    def __init__(
        self,
        database: Database,
        executor: NftablesHealingExecutor,
        completion_listener: Callable[[dict[str, Any], dict[str, Any] | None, str | None], None]
        | None = None,
    ) -> None:
        self.database = database
        self.executor = executor
        self.completion_listener = completion_listener

    def prepare(self) -> None:
        self.executor.prepare()

    def process_one(self) -> bool:
        request = self.database.claim_healing_request()
        if request is None:
            return False
        result: dict[str, Any] | None = None
        error: str | None = None
        try:
            result = self.executor.execute(request)
        except HealingActionError as exc:
            error = str(exc)
            self.database.complete_healing_request(
                request["request_id"], "failed", error=error
            )
        else:
            if request["action_id"] == "ESC-03":
                result["snapshot"] = self.database.device_incident_summary(
                    request["device_id"]
                )
            self.database.complete_healing_request(
                request["request_id"], "succeeded", result=result
            )
        if self.completion_listener is not None:
            try:
                self.completion_listener(request, result, error)
            except Exception:
                LOGGER.exception("Healing completion listener failed")
        return True
