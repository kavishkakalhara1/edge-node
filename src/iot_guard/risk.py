from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class RiskUpdate:
    previous: float
    decayed: float
    current: float
    severity: float
    level: str


def risk_level(score: float) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def update_risk(
    current_score: float,
    last_updated: datetime | None,
    inference: dict,
    half_life_hours: float = 6.0,
    now: datetime | None = None,
) -> RiskUpdate:
    now = now or datetime.now(timezone.utc)
    elapsed_hours = 0.0
    if last_updated is not None:
        if last_updated.tzinfo is None:
            last_updated = last_updated.replace(tzinfo=timezone.utc)
        elapsed_hours = max(0.0, (now - last_updated).total_seconds() / 3600)
    decayed = current_score * math.pow(0.5, elapsed_hours / half_life_hours)
    severity = 0.0
    if inference.get("is_anomaly"):
        point_ratio = max(0.0, float(inference.get("point_ratio", 0.0)) - 1.0)
        temporal_ratio = max(0.0, float(inference.get("temporal_ratio", 0.0)) - 1.0)
        fused_ratio = max(0.0, float(inference.get("fused_ratio", 0.0)) - 1.0)
        severity = min(3.0, max(point_ratio, temporal_ratio, fused_ratio))
        increment = 12.0 + 9.0 * severity
        if inference.get("anomaly_type") == "point_and_temporal":
            increment += 10.0
        current = min(100.0, decayed + increment)
    else:
        current = max(0.0, decayed - 0.25)
    return RiskUpdate(current_score, decayed, current, severity, risk_level(current))
