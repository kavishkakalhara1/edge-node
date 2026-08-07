from __future__ import annotations

import argparse
import json
import logging
import os
import random
import signal
import socket
import time
import urllib.request
from dataclasses import dataclass

LOGGER = logging.getLogger("iot-test-device")


@dataclass(frozen=True)
class Profile:
    interval_seconds: float
    packets_per_interval: int
    payload_bytes: int
    health_interval_seconds: float


PROFILES = {
    "normal": Profile(5.0, 1, 180, 60.0),
    "burst": Profile(0.1, 10, 900, 10.0),
}


@dataclass(frozen=True)
class Settings:
    gateway: str
    udp_port: int
    dashboard_port: int
    profile_name: str
    device_name: str
    random_seed: int

    @classmethod
    def from_env(cls, profile_override: str | None = None) -> "Settings":
        profile_name = profile_override or os.getenv("IOT_TEST_PROFILE", "normal")
        if profile_name not in PROFILES:
            choices = ", ".join(sorted(PROFILES))
            raise ValueError(f"Unknown profile {profile_name!r}; choose one of: {choices}")
        return cls(
            gateway=os.getenv("IOT_TEST_GATEWAY", "10.42.0.1"),
            udp_port=int(os.getenv("IOT_TEST_UDP_PORT", "9999")),
            dashboard_port=int(os.getenv("IOT_TEST_DASHBOARD_PORT", "8080")),
            profile_name=profile_name,
            device_name=os.getenv("IOT_TEST_DEVICE_NAME", socket.gethostname()),
            random_seed=int(os.getenv("IOT_TEST_RANDOM_SEED", "2025")),
        )


class Sensor:
    def __init__(self, device_name: str, seed: int):
        self.device_name = device_name
        self.random = random.Random(seed)
        self.sequence = 0

    def sample(self, target_bytes: int) -> bytes:
        self.sequence += 1
        reading = {
            "device": self.device_name,
            "sequence": self.sequence,
            "timestamp": round(time.time(), 3),
            "temperature_c": round(22.0 + self.random.uniform(-0.6, 0.6), 2),
            "humidity_percent": round(48.0 + self.random.uniform(-1.5, 1.5), 2),
            "status": "ok",
        }
        encoded = json.dumps(reading, separators=(",", ":")).encode("ascii")
        if len(encoded) < target_bytes:
            reading["padding"] = ""
            encoded = json.dumps(reading, separators=(",", ":")).encode("ascii")
            reading["padding"] = "x" * max(0, target_bytes - len(encoded))
            encoded = json.dumps(reading, separators=(",", ":")).encode("ascii")
        return encoded[:target_bytes]


class TrafficGenerator:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.profile = PROFILES[settings.profile_name]
        self.sensor = Sensor(settings.device_name, settings.random_seed)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.stopping = False

    def stop(self, _signum: int | None = None, _frame: object | None = None) -> None:
        self.stopping = True

    def send_telemetry(self) -> None:
        destination = (self.settings.gateway, self.settings.udp_port)
        for _ in range(self.profile.packets_per_interval):
            payload = self.sensor.sample(self.profile.payload_bytes)
            self.socket.sendto(payload, destination)

    def check_dashboard(self) -> None:
        url = f"http://{self.settings.gateway}:{self.settings.dashboard_port}/"
        try:
            with urllib.request.urlopen(url, timeout=3) as response:
                response.read(256)
            LOGGER.info("Dashboard check succeeded")
        except (OSError, urllib.error.URLError) as error:
            LOGGER.warning("Dashboard check failed: %s", error)

    def run(self, duration_seconds: float | None = None) -> None:
        started = time.monotonic()
        next_health_check = started
        LOGGER.info(
            "Starting %s profile toward %s (Ctrl+C to stop)",
            self.settings.profile_name,
            self.settings.gateway,
        )
        try:
            while not self.stopping:
                now = time.monotonic()
                if duration_seconds is not None and now - started >= duration_seconds:
                    break
                self.send_telemetry()
                if now >= next_health_check:
                    self.check_dashboard()
                    next_health_check = now + self.profile.health_interval_seconds
                time.sleep(self.profile.interval_seconds)
        finally:
            self.socket.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate controlled IoT test traffic")
    parser.add_argument("--profile", choices=sorted(PROFILES), help="override IOT_TEST_PROFILE")
    parser.add_argument("--duration", type=float, help="stop after this many seconds")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        settings = Settings.from_env(args.profile)
    except ValueError as error:
        raise SystemExit(str(error)) from error
    generator = TrafficGenerator(settings)
    signal.signal(signal.SIGTERM, generator.stop)
    signal.signal(signal.SIGINT, generator.stop)
    generator.run(args.duration)


if __name__ == "__main__":
    main()
