from __future__ import annotations

from detection_engine.models.entities import RiskLevel


def risk_from_confidence(confidence: float) -> RiskLevel:
    if confidence >= 0.90:
        return RiskLevel.CRITICAL
    if confidence >= 0.70:
        return RiskLevel.HIGH
    if confidence >= 0.50:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW
