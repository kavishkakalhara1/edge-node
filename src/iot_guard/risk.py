from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class RiskUpdate:
    previous: float
    decayed: float
    current: float
    severity: float
    level: str
    consecutive_anomalies: int


def risk_level(score: float) -> str:
    if score >= 0.75:
        return "critical"
    if score >= 0.50:
        return "high"
    if score >= 0.25:
        return "medium"
    return "low"


def update_risk(
    current_score: float,
    last_updated: datetime | None,
    inference: dict,
    half_life_hours: float = 6.0,
    now: datetime | None = None,
    consecutive_anomalies: int = 0,
) -> RiskUpdate:
    del half_life_hours, last_updated, now
    baseline = max(0.05, min(float(current_score), 1.0))
    severity = 0.0
    if inference.get("is_anomaly"):
        gru_score = min(1.0, max(0.0, float(inference.get("gru_score", 0.0))))
        svdd_score = min(1.0, max(0.0, float(inference.get("svdd_score", 0.0))))
        consecutive_anomalies = min(5, consecutive_anomalies + 1)
        repeat_boost = min(0.20, max(0, consecutive_anomalies - 1) * 0.05)
        severity = 0.5 * (0.35 + 0.45 * gru_score + 0.40 * svdd_score + repeat_boost)
        current = min(1.0, baseline + severity)
    else:
        consecutive_anomalies = 0
        current = max(baseline - 0.04, 0.05)
    return RiskUpdate(
        current_score,
        baseline,
        current,
        severity,
        risk_level(current),
        consecutive_anomalies,
    )
