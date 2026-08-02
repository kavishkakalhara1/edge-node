from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

from .config import Settings
from .database import Database
from .model import ProductionEnsemble


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
    verify = subcommands.add_parser("verify-model")
    verify.add_argument("directory", type=Path, nargs="?")
    args = parser.parse_args()
    settings = Settings.from_env()
    if args.command == "init-db":
        Database(settings.database_path).initialize()
        print(f"Initialized {settings.database_path}")
    elif args.command == "check":
        check(settings)
    elif args.command == "verify-model":
        verify_artifacts(args.directory or settings.artifact_dir)


if __name__ == "__main__":
    main()
