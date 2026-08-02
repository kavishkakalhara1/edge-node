from __future__ import annotations

import hashlib
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import torch
import torch.nn as nn


class DeepSVDDEncoder(nn.Module):
    def __init__(self, input_size: int, hidden_size: int, embedding_size: int):
        super().__init__()
        self.network = nn.Sequential(
            nn.Linear(input_size, hidden_size, bias=False),
            nn.LeakyReLU(negative_slope=0.1),
            nn.Linear(hidden_size, embedding_size, bias=False),
        )

    def forward(self, inputs: torch.Tensor) -> torch.Tensor:
        return self.network(inputs)


class GRUNextStepPredictor(nn.Module):
    def __init__(self, input_size: int, hidden_size: int, layers: int, dropout: float):
        super().__init__()
        self.gru = nn.GRU(
            input_size=input_size,
            hidden_size=hidden_size,
            num_layers=layers,
            batch_first=True,
            dropout=dropout if layers > 1 else 0.0,
        )
        self.output = nn.Sequential(nn.Dropout(dropout), nn.Linear(hidden_size, input_size))

    def forward(self, inputs: torch.Tensor) -> torch.Tensor:
        _, hidden = self.gru(inputs)
        return self.output(hidden[-1])


class ProductionEnsemble:
    def __init__(self, artifact_dir: Path):
        self.artifact_dir = artifact_dir
        self._verify_manifest()
        self.metadata = json.loads((artifact_dir / "metadata.json").read_text())
        self.feature_columns: list[str] = self.metadata["feature_columns"]
        self.preprocessor = joblib.load(artifact_dir / "preprocessor.joblib")
        self.point_model = DeepSVDDEncoder(
            len(self.feature_columns),
            self.metadata["svdd"]["hidden_size"],
            self.metadata["svdd"]["embedding_size"],
        )
        self.point_model.load_state_dict(
            torch.load(artifact_dir / "point_svdd.pt", map_location="cpu", weights_only=True)
        )
        self.temporal_model = GRUNextStepPredictor(
            len(self.feature_columns),
            self.metadata["gru"]["hidden_size"],
            self.metadata["gru"]["layers"],
            self.metadata["gru"]["dropout"],
        )
        self.temporal_model.load_state_dict(
            torch.load(artifact_dir / "temporal_gru.pt", map_location="cpu", weights_only=True)
        )
        self.point_model.eval()
        self.temporal_model.eval()
        self.svdd_center = torch.tensor(self.metadata["svdd"]["center"], dtype=torch.float32)

    def _verify_manifest(self) -> None:
        manifest = json.loads((self.artifact_dir / "manifest.json").read_text())
        for filename, expected_hash in manifest["sha256"].items():
            path = self.artifact_dir / filename
            if not path.is_file():
                raise RuntimeError(f"Missing model artifact: {filename}")
            actual_hash = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual_hash != expected_hash:
                raise RuntimeError(f"Model artifact integrity failure: {filename}")

    def _frame(self, row: dict[str, float]) -> pd.DataFrame:
        missing = sorted(set(self.feature_columns) - set(row))
        if missing:
            raise ValueError(f"Feature window is missing columns: {missing}")
        return pd.DataFrame([row], columns=self.feature_columns).apply(pd.to_numeric, errors="coerce")

    def score_point(self, point_window: dict[str, float]) -> dict[str, float | bool]:
        point_x = self.preprocessor.transform(self._frame(point_window)).astype(np.float32)
        with torch.inference_mode():
            embedding = self.point_model(torch.from_numpy(point_x))
            raw = torch.sum((embedding - self.svdd_center) ** 2, dim=1).item()
        score = (raw - self.metadata["point_center"]) / self.metadata["point_scale"]
        return {
            "point_score": float(score),
            "point_anomaly": bool(score > self.metadata["point_threshold"]),
        }

    def score_windows(
        self,
        point_window: dict[str, float],
        temporal_windows: list[dict[str, float]],
    ) -> dict[str, float | bool | str]:
        expected = self.metadata["temporal_input_windows"]
        if len(temporal_windows) != expected:
            raise ValueError(f"Expected {expected} temporal windows, received {len(temporal_windows)}")
        point_result = self.score_point(point_window)
        temporal_frame = pd.DataFrame(temporal_windows, columns=self.feature_columns)
        temporal_x = self.preprocessor.transform(temporal_frame).astype(np.float32)
        history = temporal_x[:-1][None, :, :]
        observed = temporal_x[-1]
        with torch.inference_mode():
            predicted = self.temporal_model(torch.from_numpy(history)).numpy()[0]
        temporal_raw = float(np.mean((predicted - observed) ** 2))
        temporal_score = (
            temporal_raw - self.metadata["temporal_center"]
        ) / self.metadata["temporal_scale"]
        ensemble_score = (
            self.metadata["point_weight"] * point_result["point_score"]
            + self.metadata["temporal_weight"] * temporal_score
        )
        temporal_anomaly = temporal_score > self.metadata["temporal_threshold"]
        fused_anomaly = ensemble_score > self.metadata["ensemble_threshold"]
        point_anomaly = bool(point_result["point_anomaly"])
        is_anomaly = point_anomaly or temporal_anomaly or fused_anomaly
        if point_anomaly and temporal_anomaly:
            anomaly_type = "point_and_temporal"
        elif point_anomaly:
            anomaly_type = "point"
        elif temporal_anomaly:
            anomaly_type = "temporal"
        elif fused_anomaly:
            anomaly_type = "fused"
        else:
            anomaly_type = "normal"
        return {
            **point_result,
            "temporal_score": float(temporal_score),
            "temporal_anomaly": bool(temporal_anomaly),
            "ensemble_score": float(ensemble_score),
            "fused_score_anomaly": bool(fused_anomaly),
            "is_anomaly": bool(is_anomaly),
            "anomaly_type": anomaly_type,
            "decision": "anomaly" if is_anomaly else "normal",
        }
