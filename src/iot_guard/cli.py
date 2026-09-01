from __future__ import annotations

import argparse
import gc
import hashlib
import json
import os
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path

from .config import Settings
from .database import Database
from .model import ProductionEnsemble


def _latency_summary(samples: list[float]) -> dict[str, float | int]:
    ordered = sorted(samples)

    def percentile(fraction: float) -> float:
        index = min(len(ordered) - 1, int((len(ordered) - 1) * fraction))
        return round(ordered[index], 3)

    mean_ms = statistics.fmean(samples)
    return {
        "iterations": len(samples),
        "mean_ms": round(mean_ms, 3),
        "throughput_per_second": round(1000 / mean_ms, 3),
        "p50_ms": percentile(0.50),
        "p95_ms": percentile(0.95),
        "p99_ms": percentile(0.99),
        "min_ms": round(ordered[0], 3),
        "max_ms": round(ordered[-1], 3),
    }


def benchmark_latency(settings: Settings, iterations: int, warmup: int) -> dict:
    load_started = time.perf_counter_ns()
    model = ProductionEnsemble(
        settings.artifact_dir,
        cpu_threads=settings.model_cpu_threads,
        allow_fallback=settings.model_allow_fallback,
    )
    model_load_ms = (time.perf_counter_ns() - load_started) / 1_000_000
    row = {name: 0.0 for name in model.feature_columns}
    window = [row.copy() for _ in range(model.window_size)]

    for _ in range(warmup):
        model.score_window(window)

    def measure(callback) -> dict[str, float | int]:
        samples = []
        gc.collect()
        gc.disable()
        try:
            for _ in range(iterations):
                started = time.perf_counter_ns()
                callback()
                samples.append((time.perf_counter_ns() - started) / 1_000_000)
        finally:
            gc.enable()
        return _latency_summary(samples)

    result = {
        "measured_at": datetime.now(timezone.utc).isoformat(),
        "artifact_version": model.model_version,
        "model_load_ms": round(model_load_ms, 3),
        "window_size": model.window_size,
        "feature_count": model.input_dim,
        "cpu_threads": settings.model_cpu_threads,
        "fallback": model.is_fallback,
        "fused_decision": measure(lambda: model.score_window(window)),
    }
    output = settings.database_path.parent / "latency-benchmark.json"
    output.write_text(json.dumps(result, indent=2) + "\n")
    return result


def check(settings: Settings) -> None:
    model = ProductionEnsemble(
        settings.artifact_dir,
        cpu_threads=settings.model_cpu_threads,
        allow_fallback=settings.model_allow_fallback,
    )
    Database(settings.database_path).initialize()
    interface_names = set(settings.capture_interfaces)
    interface_names.update(
        {
            settings.hotspot_interface,
            settings.monitor_interface,
            settings.cloud_uplink_interface,
        }
    )
    interfaces = [Path("/sys/class/net") / name for name in sorted(interface_names)]
    report = {
        "artifact_version": model.model_version,
        "features": len(model.feature_columns),
        "window_size": model.window_size,
        "raw_threshold": model.threshold,
        "fallback": model.is_fallback,
        "database": str(settings.database_path),
        "database_writable": os.access(settings.database_path.parent, os.W_OK),
        "identity_secret_present": settings.identity_secret_file.is_file(),
        "dhcp_lease_file": str(settings.dhcp_lease_file),
        "dhcp_lease_file_present": settings.dhcp_lease_file.is_file(),
        "dhcp_lease_file_readable": os.access(settings.dhcp_lease_file, os.R_OK),
        "device_registry": str(settings.device_registry_path),
        "device_registry_present": settings.device_registry_path.is_file(),
        "device_registry_readable": os.access(settings.device_registry_path, os.R_OK),
        "network_roles": {
            "iot_hotspot": settings.hotspot_interface,
            "cloud_uplink": settings.cloud_uplink_interface,
            "separate": settings.hotspot_interface != settings.cloud_uplink_interface,
        },
        "interfaces": {path.name: path.exists() for path in interfaces},
    }
    print(json.dumps(report, indent=2))


def verify_artifacts(directory: Path) -> None:
    manifest = json.loads((directory / "manifest.json").read_text())
    for filename, expected in manifest["sha256"].items():
        actual = hashlib.sha256((directory / filename).read_bytes()).hexdigest()
        if actual != expected:
            raise SystemExit(f"Integrity failure: {filename}")
    print(f"Verified {len(manifest['sha256'])} model artifacts")


def main() -> None:
    parser = argparse.ArgumentParser(prog="iot-guard")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("init-db")
    subcommands.add_parser("check")
    benchmark = subcommands.add_parser("benchmark-latency")
    benchmark.add_argument("--iterations", type=int, default=300)
    benchmark.add_argument("--warmup", type=int, default=25)
    verify = subcommands.add_parser("verify-model")
    verify.add_argument("directory", type=Path, nargs="?")
    args = parser.parse_args()
    settings = Settings.from_env()
    if args.command == "init-db":
        Database(settings.database_path).initialize()
        print(f"Initialized {settings.database_path}")
    elif args.command == "check":
        check(settings)
    elif args.command == "benchmark-latency":
        if args.iterations < 1 or args.warmup < 0:
            parser.error("iterations must be positive and warmup cannot be negative")
        print(json.dumps(benchmark_latency(settings, args.iterations, args.warmup), indent=2))
    elif args.command == "verify-model":
        verify_artifacts(args.directory or settings.artifact_dir)


if __name__ == "__main__":
    main()
