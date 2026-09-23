from __future__ import annotations

from detection_engine.models.entities import DetectionCandidate, RiskLevel, ValidationStatus
from detection_engine.rules.allowlists import is_placeholder
from detection_engine.rules.risk_rules import risk_from_confidence


CRITICAL_TYPES = {
    "AWS_ACCESS_KEY", "OPENAI_API_KEY",
    "AWS_SECRET_ACCESS_KEY", "ANTHROPIC_API_KEY", "HUGGINGFACE_TOKEN", "AZURE_STORAGE_KEY", "GCP_SERVICE_ACCOUNT_KEY", "SENDGRID_API_KEY", "NPM_TOKEN", "SLACK_WEBHOOK", "TELEGRAM_BOT_TOKEN", "GITHUB_TOKEN", "GITLAB_TOKEN", "GOOGLE_API_KEY", "STRIPE_SECRET_KEY",
    "SLACK_TOKEN", "BEARER_TOKEN", "DATABASE_CONNECTION_STRING", "SSH_PRIVATE_KEY",
    "PEM_PRIVATE_KEY", "PGP_PRIVATE_KEY", "PASSWORD", "URL_WITH_CREDENTIALS",
}


def classify_entity(candidate: DetectionCandidate) -> DetectionCandidate:
    risk = risk_from_confidence(candidate.confidence)
    if candidate.entity_type in CRITICAL_TYPES and candidate.confidence >= 0.70:
        risk = RiskLevel.CRITICAL
    if candidate.entity_type == "CREDIT_CARD_NUMBER" and candidate.validation_status == ValidationStatus.CHECKSUM_VALID:
        risk = RiskLevel.CRITICAL if candidate.confidence >= 0.70 else RiskLevel.HIGH
    if candidate.entity_type == "HIGH_ENTROPY_SECRET" and candidate.confidence < 0.80:
        risk = RiskLevel.MEDIUM
    if candidate.entity_type in {"PERSON_NAME", "LOCATION", "ORGANIZATION"} and candidate.confidence < 0.75:
        risk = RiskLevel.LOW if candidate.entity_type != "PERSON_NAME" else RiskLevel.MEDIUM
    if is_placeholder(candidate.value) and risk == RiskLevel.CRITICAL:
        risk = RiskLevel.HIGH
    return candidate.model_copy(update={"risk_level": risk})


def overall_risk(candidates: list[DetectionCandidate]) -> tuple[RiskLevel, float]:
    if not candidates:
        return RiskLevel.LOW, 0.0
    rank = {RiskLevel.LOW: 1, RiskLevel.MEDIUM: 2, RiskLevel.HIGH: 3, RiskLevel.CRITICAL: 4}
    highest = max(candidates, key=lambda item: (rank[item.risk_level], item.confidence))
    score = max(item.confidence for item in candidates)
    if any(item.risk_level == RiskLevel.CRITICAL for item in candidates):
        score = max(score, 0.90)
    return highest.risk_level, round(score, 3)
