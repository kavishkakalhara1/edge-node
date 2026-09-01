from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import asdict
from typing import Callable

from .capture import WirelessObservation


class WirelessAttackDetector:
    def __init__(
        self,
        expected_ssid: str,
        expected_bssid: str | None,
        *,
        clock: Callable[[], float] = time.monotonic,
        window_seconds: float = 10.0,
        cooldown_seconds: float = 30.0,
    ) -> None:
        self.expected_ssid = expected_ssid
        self.expected_bssid = expected_bssid
        self.clock = clock
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        self.frames: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self.last_alert: dict[tuple[str, str], float] = {}

    def observe(self, observation: WirelessObservation) -> list[dict]:
        alerts = []
        if (
            observation.frame_type == 0
            and observation.frame_subtype == 8
            and observation.ssid == self.expected_ssid
            and observation.bssid
            and self.expected_bssid
            and observation.bssid != self.expected_bssid
        ):
            alert = self._alert("evil_twin", observation.bssid, 1, observation)
            if alert is not None:
                alerts.append(alert)

        attack = self._rate_attack(observation)
        if attack is None:
            return alerts
        attack_class, threshold = attack
        source = observation.src_mac or "unknown"
        key = (attack_class, source)
        now = self.clock()
        samples = self.frames[key]
        samples.append(now)
        while samples and now - samples[0] > self.window_seconds:
            samples.popleft()
        if len(samples) >= threshold:
            alert = self._alert(attack_class, source, len(samples), observation)
            if alert is not None:
                alerts.append(alert)
        return alerts

    @staticmethod
    def _rate_attack(observation: WirelessObservation) -> tuple[str, int] | None:
        if observation.frame_type != 0:
            return None
        if observation.frame_subtype in {10, 12}:
            return "deauthentication_flood", 5
        if observation.frame_subtype in {0, 2, 11}:
            return "authentication_flood", 20
        if observation.frame_subtype == 4:
            return "probe_request_flood", 50
        return None

    def _alert(
        self,
        attack_class: str,
        source: str,
        count: int,
        observation: WirelessObservation,
    ) -> dict | None:
        now = self.clock()
        key = (attack_class, source)
        if now - self.last_alert.get(key, float("-inf")) < self.cooldown_seconds:
            return None
        self.last_alert[key] = now
        return {
            "attack_class": attack_class,
            "source_mac": observation.src_mac,
            "target_mac": observation.dst_mac,
            "bssid": observation.bssid,
            "ssid": observation.ssid,
            "frame_count": count,
            "window_seconds": self.window_seconds,
            "signal_dbm": observation.signal_dbm,
            "channel_frequency": observation.channel_frequency,
            "evidence": asdict(observation),
        }