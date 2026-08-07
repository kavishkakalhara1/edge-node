from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import torch
import torch.nn as nn


class ArtifactError(RuntimeError):
    pass


class GRUFeatureExtractor(nn.Module):
    def __init__(self, input_dim: int, hidden_dim: int):
        super().__init__()
        self.gru = nn.GRU(input_dim, hidden_dim, batch_first=True)
        self.decoder = nn.Linear(hidden_dim, input_dim)

    def forward(self, inputs: torch.Tensor) -> torch.Tensor:
        _, hidden = self.gru(inputs)
        return hidden[-1]


class DeepSVDDHead(nn.Module):
    def __init__(self, fused_dim: int, rep_dim: int):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(fused_dim, 32, bias=False),
            nn.ReLU(),
            nn.Linear(32, 32, bias=False),
            nn.ReLU(),
            nn.Linear(32, rep_dim, bias=False),
        )

    def forward(self, inputs: torch.Tensor) -> torch.Tensor:
        return self.net(inputs)


class LegacyPointSVDD(nn.Module):
    def __init__(self, input_size: int, hidden_size: int, embedding_size: int):
        super().__init__()
        self.network = nn.Sequential(
            nn.Linear(input_size, hidden_size, bias=False),
            nn.LeakyReLU(negative_slope=0.1),
            nn.Linear(hidden_size, embedding_size, bias=False),
        )

    def forward(self, inputs: torch.Tensor) -> torch.Tensor:
        return self.network(inputs)


class ProductionEnsemble:
    REQUIRED_ARTIFACTS = (
        "pipeline_artifacts_gru_svdd.joblib",
        "gru_feature_extractor_svdd.pth",
        "deep_svdd_head.pth",
    )

    def __init__(
        self,
        artifact_dir: Path,
        *,
        cpu_threads: int = 2,
        allow_fallback: bool = False,
    ):
        self.artifact_dir = artifact_dir
        torch.set_num_threads(max(1, cpu_threads))
        try:
            self._load_fused()
        except Exception as error:
            if not allow_fallback:
                if isinstance(error, ArtifactError):
                    raise
                raise ArtifactError(f"Unable to load fused GRU-SVDD artifacts: {error}") from error
            self._load_legacy_point(error)

    def _load_fused(self) -> None:
        self._verify_manifest(self.REQUIRED_ARTIFACTS)
        artifact_path = self.artifact_dir / "pipeline_artifacts_gru_svdd.joblib"
        try:
            artifacts: dict[str, Any] = joblib.load(artifact_path)
        except Exception as error:
            raise ArtifactError(f"Cannot deserialize {artifact_path.name}: {error}") from error
        required_keys = {
            "scaler", "feature_columns", "svdd_center", "input_dim", "hidden_dim",
            "rep_dim", "fused_dim", "window_size", "optimal_threshold",
        }
        missing_keys = sorted(required_keys - artifacts.keys())
        if missing_keys:
            raise ArtifactError(f"Pipeline artifact is missing keys: {missing_keys}")

        self.feature_columns = list(artifacts["feature_columns"])
        self.input_dim = int(artifacts["input_dim"])
        self.hidden_dim = int(artifacts["hidden_dim"])
        self.rep_dim = int(artifacts["rep_dim"])
        self.fused_dim = int(artifacts["fused_dim"])
        self.window_size = int(artifacts["window_size"])
        self.threshold = float(artifacts["optimal_threshold"])
        self.preprocessor = artifacts["scaler"]
        center = np.asarray(artifacts["svdd_center"], dtype=np.float32)

        if len(self.feature_columns) != self.input_dim:
            raise ArtifactError(
                f"feature_columns has {len(self.feature_columns)} entries, expected {self.input_dim}"
            )
        if len(set(self.feature_columns)) != len(self.feature_columns):
            raise ArtifactError("feature_columns contains duplicate names")
        if getattr(self.preprocessor, "n_features_in_", None) != self.input_dim:
            raise ArtifactError("Scaler input dimension does not match input_dim")
        if self.fused_dim != self.input_dim + self.hidden_dim:
            raise ArtifactError("fused_dim must equal input_dim + hidden_dim")
        if center.shape != (self.rep_dim,):
            raise ArtifactError(f"SVDD center shape is {center.shape}, expected {(self.rep_dim,)}")
        if self.window_size < 1 or not math.isfinite(self.threshold):
            raise ArtifactError("window_size and optimal_threshold must be valid")

        self.gru = GRUFeatureExtractor(self.input_dim, self.hidden_dim)
        self.head = DeepSVDDHead(self.fused_dim, self.rep_dim)
        self._load_state(self.gru, "gru_feature_extractor_svdd.pth")
        self._load_state(self.head, "deep_svdd_head.pth")
        self.gru.eval()
        self.head.eval()
        self.svdd_center = torch.from_numpy(center)
        version_hash = hashlib.sha256(
            (self.artifact_dir / "pipeline_artifacts_gru_svdd.joblib").read_bytes()
        ).hexdigest()[:12]
        self.model_version = f"gru-svdd-{version_hash}"
        self.is_fallback = False
        self.metadata = {
            "artifact_version": self.model_version,
            "feature_count": self.input_dim,
            "window_size": self.window_size,
            "raw_threshold": self.threshold,
            "point_threshold": self.threshold,
            "temporal_threshold": self.threshold,
            "ensemble_threshold": self.threshold,
        }

    def _load_legacy_point(self, fused_error: Exception) -> None:
        self._verify_manifest(("metadata.json", "preprocessor.joblib", "point_svdd.pt"))
        metadata = json.loads((self.artifact_dir / "metadata.json").read_text())
        self.feature_columns = list(metadata["feature_columns"])
        self.input_dim = len(self.feature_columns)
        self.hidden_dim = 0
        self.rep_dim = int(metadata["svdd"]["embedding_size"])
        self.fused_dim = self.input_dim
        self.window_size = 1
        self.preprocessor = joblib.load(self.artifact_dir / "preprocessor.joblib")
        self.threshold = float(metadata["point_threshold"])
        self.legacy_center = torch.tensor(metadata["svdd"]["center"], dtype=torch.float32)
        self.legacy_center_offset = float(metadata["point_center"])
        self.legacy_scale = float(metadata["point_scale"])
        self.legacy_model = LegacyPointSVDD(
            self.input_dim,
            int(metadata["svdd"]["hidden_size"]),
            self.rep_dim,
        )
        self._load_state(self.legacy_model, "point_svdd.pt")
        self.legacy_model.eval()
        self.model_version = f"legacy-point-{metadata['artifact_version']}"
        self.is_fallback = True
        self.fallback_reason = str(fused_error)
        self.metadata = {
            "artifact_version": self.model_version,
            "feature_count": self.input_dim,
            "window_size": 1,
            "raw_threshold": self.threshold,
            "point_threshold": self.threshold,
            "temporal_threshold": self.threshold,
            "ensemble_threshold": self.threshold,
        }

    def activate_fallback(self, reason: str) -> None:
        if self.is_fallback:
            return
        self._load_legacy_point(RuntimeError(reason))

    def _verify_manifest(self, filenames: tuple[str, ...]) -> None:
        manifest_path = self.artifact_dir / "manifest.json"
        if not manifest_path.is_file():
            raise ArtifactError("Missing model artifact: manifest.json")
        try:
            hashes = json.loads(manifest_path.read_text())["sha256"]
        except (KeyError, json.JSONDecodeError) as error:
            raise ArtifactError(f"Invalid manifest.json: {error}") from error
        for filename in filenames:
            path = self.artifact_dir / filename
            if not path.is_file():
                raise ArtifactError(f"Missing model artifact: {filename}")
            expected = hashes.get(filename)
            if expected is None:
                raise ArtifactError(f"manifest.json has no hash for {filename}")
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual != expected:
                raise ArtifactError(f"Model artifact integrity failure: {filename}")

    def _load_state(self, model: nn.Module, filename: str) -> None:
        try:
            state = torch.load(
                self.artifact_dir / filename, map_location="cpu", weights_only=True
            )
            model.load_state_dict(state, strict=True)
        except Exception as error:
            raise ArtifactError(f"Incompatible {filename}: {error}") from error

    def preprocess(self, records: list[dict[str, float]]) -> np.ndarray:
        if not records:
            raise ValueError("At least one aggregated record is required")
        rows: list[list[float]] = []
        for index, record in enumerate(records):
            missing = [name for name in self.feature_columns if name not in record]
            if missing:
                raise ValueError(f"Record {index} is missing required features: {missing}")
            try:
                row = [float(record[name]) for name in self.feature_columns]
            except (TypeError, ValueError) as error:
                raise ValueError(f"Record {index} contains a non-numeric feature") from error
            if not np.isfinite(row).all():
                raise ValueError(f"Record {index} contains a non-finite feature")
            rows.append(row)
        values = np.asarray(rows, dtype=np.float32)
        if values.shape[1] != self.input_dim:
            raise ValueError(f"Input dimension is {values.shape[1]}, expected {self.input_dim}")
        scaled = self.preprocessor.transform(values)
        scaled = np.asarray(scaled, dtype=np.float32)
        if scaled.shape != values.shape:
            raise ArtifactError(f"Preprocessor returned shape {scaled.shape}, expected {values.shape}")
        return scaled

    @staticmethod
    def classify(score: float, threshold: float) -> bool:
        return bool(score > threshold)

    def score_window(self, records: list[dict[str, float]]) -> dict[str, Any]:
        if len(records) != self.window_size:
            raise ValueError(f"Expected {self.window_size} records, received {len(records)}")
        scaled = self.preprocess(records)
        inputs = torch.from_numpy(scaled).unsqueeze(0)
        with torch.inference_mode():
            if self.is_fallback:
                embedding = self.legacy_model(inputs[:, -1, :])
                distance = torch.sum((embedding - self.legacy_center) ** 2, dim=1).item()
                score = (distance - self.legacy_center_offset) / self.legacy_scale
            else:
                temporal_embedding = self.gru(inputs)
                fused = torch.cat((inputs[:, -1, :], temporal_embedding), dim=1)
                if fused.shape[1] != self.fused_dim:
                    raise ArtifactError(
                        f"Fused tensor has {fused.shape[1]} features, expected {self.fused_dim}"
                    )
                representation = self.head(fused)
                score = torch.sum(
                    (representation - self.svdd_center) ** 2, dim=1
                ).item()
        is_anomaly = self.classify(score, self.threshold)
        return {
            "raw_score": float(score),
            "raw_threshold": self.threshold,
            "is_anomaly": is_anomaly,
            "decision": "anomaly" if is_anomaly else "normal",
            "model_version": self.model_version,
            "fallback": self.is_fallback,
        }
