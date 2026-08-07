import math
import hashlib
import json
import shutil
from pathlib import Path

import joblib
import numpy as np
import pytest

from iot_guard.model import ArtifactError, ProductionEnsemble


@pytest.fixture(scope="module")
def model():
    return ProductionEnsemble(Path("model"), cpu_threads=1)


def row(model, offset=0.0):
    return {name: float(index) + offset for index, name in enumerate(model.feature_columns)}


def test_exported_artifacts_have_compatible_dimensions(model):
    assert len(model.feature_columns) == model.input_dim == 36
    assert model.hidden_dim == 64
    assert model.fused_dim == model.input_dim + model.hidden_dim == 100
    assert model.rep_dim == 8
    assert model.svdd_center.shape == (8,)
    assert model.window_size == 4


def test_preprocessing_uses_exported_feature_order(model):
    record = dict(reversed(list(row(model).items())))
    record.update({"label": "attack", "timestamp": "ignored", "device_id": "ignored"})
    actual = model.preprocess([record])
    ordered = np.asarray([[record[name] for name in model.feature_columns]], dtype=np.float32)
    expected = model.preprocessor.transform(ordered).astype(np.float32)
    np.testing.assert_array_equal(actual, expected)


def test_missing_feature_is_rejected(model):
    record = row(model)
    missing = model.feature_columns[3]
    del record[missing]
    with pytest.raises(ValueError, match=missing):
        model.preprocess([record])


def test_complete_window_produces_one_deterministic_raw_score(model):
    records = [row(model, offset) for offset in range(model.window_size)]
    first = model.score_window(records)
    second = model.score_window(records)
    assert math.isfinite(first["raw_score"])
    assert first == second
    assert first["raw_threshold"] == model.threshold
    assert first["model_version"] == model.model_version


def test_incomplete_window_is_rejected(model):
    with pytest.raises(ValueError, match="Expected 4 records"):
        model.score_window([row(model) for _ in range(3)])


def test_threshold_is_strictly_greater_than():
    assert not ProductionEnsemble.classify(0.5, 0.5)
    assert ProductionEnsemble.classify(np.nextafter(0.5, 1.0), 0.5)


def test_incompatible_pipeline_dimensions_fail_at_startup(tmp_path):
    for filename in ProductionEnsemble.REQUIRED_ARTIFACTS:
        shutil.copy2(Path("model") / filename, tmp_path / filename)
    artifacts = joblib.load(tmp_path / "pipeline_artifacts_gru_svdd.joblib")
    artifacts["fused_dim"] = 99
    joblib.dump(artifacts, tmp_path / "pipeline_artifacts_gru_svdd.joblib")
    hashes = {
        filename: hashlib.sha256((tmp_path / filename).read_bytes()).hexdigest()
        for filename in ProductionEnsemble.REQUIRED_ARTIFACTS
    }
    (tmp_path / "manifest.json").write_text(json.dumps({"sha256": hashes}))

    with pytest.raises(ArtifactError, match="fused_dim"):
        ProductionEnsemble(tmp_path, cpu_threads=1)
