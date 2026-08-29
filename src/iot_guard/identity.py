from __future__ import annotations

import hashlib
import hmac
import re
from pathlib import Path

_MAC_PATTERN = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")


def normalize_mac(mac: str) -> str:
    normalized = mac.strip().lower().replace("-", ":")
    if not _MAC_PATTERN.fullmatch(normalized):
        raise ValueError(f"Invalid MAC address: {mac!r}")
    return normalized


class DeviceIdentity:
    def __init__(self, secret: bytes):
        if len(secret) < 32:
            raise ValueError("Device identity secret must contain at least 32 bytes")
        self._secret = secret

    @classmethod
    def from_file(cls, path: Path) -> "DeviceIdentity":
        return cls(path.read_bytes())

    def device_id(self, mac: str) -> str:
        return f"id-{normalize_mac(mac).replace(':', '')}"

    def mac_fingerprint(self, mac: str) -> str:
        digest = hmac.new(self._secret, b"audit:" + normalize_mac(mac).encode(), hashlib.sha256)
        return digest.hexdigest()
