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

    return {
        "iterations": len(samples),
        "mean_ms": round(statistics.fmean(samples), 3),
        "p50_ms": percentile(0.50),
        "p95_ms": percentile(0.95),
        "p99_ms": percentile(0.99),
        "min_ms": round(ordered[0], 3),
        "max_ms": round(ordered[-1], 3),
    }


def benchmark_latency(settings: Settings, iterations: int, warmup: int) -> dict:
    load_started = time.perf_counter_ns()
    model = ProductionEnsemble(settings.artifact_dir)
    model_load_ms = (time.perf_counter_ns() - load_started) / 1_000_000
    row = {name: 0.0 for name in model.feature_columns}
    temporal = [row.copy() for _ in range(model.metadata["temporal_input_windows"])]

    for _ in range(warmup):
        model.score_point(row)
        model.score_windows(row, temporal)

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
        "artifact_version": model.metadata["artifact_version"],
        "model_load_ms": round(model_load_ms, 3),
        "point_window_seconds": 2,
        "temporal_window_seconds": 10,
        "temporal_warmup_seconds": 10 * model.metadata["temporal_input_windows"],
        "point_decision": measure(lambda: model.score_point(row)),
        "fused_decision": measure(lambda: model.score_windows(row, temporal)),
    }
    output = settings.database_path.parent / "latency-benchmark.json"
    output.write_text(json.dumps(result, indent=2) + "\n")
    return result


def check(settings: Settings) -> None:
    model = ProductionEnsemble(settings.artifact_dir)
    Database(settings.database_path).initialize()
    interfaces = [Path("/sys/class/net") / name for name in settings.capture_interfaces]
    report = {
        "artifact_version": model.metadata["artifact_version"],
        "features": len(model.feature_columns),
        "database": str(settings.database_path),
        "database_writable": os.access(settings.database_path.parent, os.W_OK),
        "identity_secret_present": settings.identity_secret_file.is_file(),
        "dhcp_lease_file_present": settings.dhcp_lease_file.is_file(),
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
