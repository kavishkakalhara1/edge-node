from __future__ import annotations

import http.client
import json
import logging
import queue
import socket
import threading
from collections.abc import Callable
from typing import Any
from urllib.parse import SplitResult, urlsplit

LOGGER = logging.getLogger(__name__)


def _bound_connection(
    target: SplitResult,
    interface: str,
    timeout_seconds: float,
) -> http.client.HTTPConnection:
    connection_type = (
        http.client.HTTPSConnection if target.scheme == "https" else http.client.HTTPConnection
    )
    connection = connection_type(target.hostname, target.port, timeout=timeout_seconds)

    def create_connection(address, timeout=timeout_seconds, source_address=None):
        del source_address
        errors = []
        for family, socktype, protocol, _name, socket_address in socket.getaddrinfo(
            *address, type=socket.SOCK_STREAM
        ):
            bound_socket = socket.socket(family, socktype, protocol)
            try:
                bound_socket.settimeout(timeout)
                bound_socket.setsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_BINDTODEVICE,
                    interface.encode("ascii") + b"\0",
                )
                bound_socket.connect(socket_address)
                return bound_socket
            except OSError as exc:
                errors.append(exc)
                bound_socket.close()
        if errors:
            raise errors[-1]
        raise OSError(f"Unable to resolve cloud API host {target.hostname}")

    connection._create_connection = create_connection
    return connection


class CloudReporter:
    def __init__(
        self,
        endpoint: str,
        uplink_interface: str,
        token: str = "",
        timeout_seconds: float = 5.0,
        queue_size: int = 100,
        sender: Callable[[dict[str, Any]], None] | None = None,
        connection_factory: Callable[
            [SplitResult, str, float], http.client.HTTPConnection
        ] = _bound_connection,
    ) -> None:
        self.endpoint = endpoint.strip()
        self.uplink_interface = uplink_interface.strip()
        self.token = token
        self.timeout_seconds = timeout_seconds
        self._connection_factory = connection_factory
        self._queue: queue.Queue[dict[str, Any] | None] = queue.Queue(maxsize=queue_size)
        self._sender = sender or self._post
        self._thread: threading.Thread | None = None
        if self.endpoint:
            if not self.uplink_interface:
                raise ValueError("Cloud uplink interface is required when cloud reporting is enabled")
            try:
                socket.if_nametoindex(self.uplink_interface)
            except OSError as exc:
                raise ValueError(
                    f"Cloud uplink interface does not exist: {self.uplink_interface}"
                ) from exc
            self._thread = threading.Thread(
                target=self._run,
                name="iot-guard-cloud-reporter",
                daemon=True,
            )
            self._thread.start()

    @property
    def enabled(self) -> bool:
        return bool(self.endpoint)

    def submit(self, payload: dict[str, Any]) -> bool:
        if not self.enabled:
            return False
        try:
            self._queue.put_nowait(payload)
        except queue.Full:
            LOGGER.error("Cloud anomaly queue is full; dropping device=%s", payload["device_id"])
            return False
        return True

    def close(self) -> None:
        if self._thread is None:
            return
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            LOGGER.warning("Cloud anomaly queue did not drain before shutdown")
            return
        self._thread.join(timeout=self.timeout_seconds + 1)

    def _run(self) -> None:
        while True:
            payload = self._queue.get()
            try:
                if payload is None:
                    return
                self._sender(payload)
            except (OSError, http.client.HTTPException, ValueError) as exc:
                LOGGER.error(
                    "Cloud anomaly delivery failed device=%s error=%s",
                    payload["device_id"],
                    exc,
                )
            finally:
                self._queue.task_done()

    def _post(self, payload: dict[str, Any]) -> None:
        target = urlsplit(self.endpoint)
        if target.scheme not in {"http", "https"} or not target.hostname:
            raise ValueError("Cloud API endpoint must be an absolute HTTP(S) URL")
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        path = target.path or "/"
        if target.query:
            path = f"{path}?{target.query}"
        connection = self._connection_factory(
            target,
            self.uplink_interface,
            self.timeout_seconds,
        )
        try:
            connection.request(
                "POST",
                path,
                body=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
                headers=headers,
            )
            response = connection.getresponse()
            if not 200 <= response.status < 300:
                raise OSError(f"Cloud API returned HTTP {response.status}")
            response.read()
        finally:
            connection.close()
