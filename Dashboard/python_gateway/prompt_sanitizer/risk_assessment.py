from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel

from detection_engine.models.entities import Category
from detection_engine.models.response import DetectedEntity, DetectionResponse

# Points an entity type contributes to the prompt risk score at full
# confidence. Credentials weigh most because a leaked secret is directly
# exploitable; contact details weigh least because they are often already
# semi-public.
ENTITY_WEIGHTS: dict[str, int] = {
    "AWS_ACCESS_KEY": 60,
    "GITHUB_TOKEN": 60,
    "GITLAB_TOKEN": 60,
    "GOOGLE_API_KEY": 60,
    "STRIPE_SECRET_KEY": 60,
    "SLACK_TOKEN": 60,
    "SSH_PRIVATE_KEY": 80,
    "PEM_PRIVATE_KEY": 80,
    "PGP_PRIVATE_KEY": 80,
    "AWS_SECRET_ACCESS_KEY": 70,
    "AZURE_STORAGE_KEY": 70,
    "GCP_SERVICE_ACCOUNT_KEY": 70,
    "OPENAI_API_KEY": 60,
    "ANTHROPIC_API_KEY": 60,
    "HUGGINGFACE_TOKEN": 60,
    "SENDGRID_API_KEY": 60,
    "NPM_TOKEN": 60,
    "SLACK_WEBHOOK": 55,
    "TELEGRAM_BOT_TOKEN": 55,
    "DATABASE_CONNECTION_STRING": 60,
    "URL_WITH_CREDENTIALS": 55,
    "BEARER_TOKEN": 55,
    "JWT_TOKEN": 50,
    "PASSWORD": 50,
    "GENERIC_API_KEY": 45,
    "HIGH_ENTROPY_SECRET": 30,
    "CREDIT_CARD_NUMBER": 50,
    "CVV": 40,
    "IBAN": 45,
    "SWIFT_BIC": 10,
    "SRI_LANKAN_NIC": 30,
    "PASSPORT_NUMBER": 35,
    "DATE_OF_BIRTH": 15,
    "EMAIL_ADDRESS": 15,
    "PHONE_NUMBER": 10,
    "IP_ADDRESS": 10,
    "IPV6_ADDRESS": 10,
    "PERSON_NAME": 10,
    "LOCATION": 5,
    "ORGANIZATION": 5,
    "PRIVATE_SOURCE_CODE": 45,
    "SOURCE_CODE": 25,
}
# Fallback for entity types without an explicit weight, by category, so a
# newly added credential rule can never be scored like a phone number.
CATEGORY_DEFAULT_WEIGHTS: dict[Category, int] = {
    Category.CREDENTIAL: 55,
    Category.FINANCIAL: 40,
    Category.PII: 15,
    Category.SOURCE_CODE: 25,
}
# Several kinds of sensitive data in one prompt (e.g. a customer's card and
# their NIC) is worse than the sum of parts: it forms a linkable record.
CATEGORY_COMBINATION_BONUS = 10

CRITICAL_THRESHOLD = 80
HIGH_THRESHOLD = 50
MEDIUM_THRESHOLD = 25


class RiskLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RecommendedAction(StrEnum):
    ALLOW = "ALLOW"
    SANITIZE = "SANITIZE"
    BLOCK = "BLOCK"


class RiskFactor(BaseModel):
    entity_type: str
    category: Category
    points: int
    reason: str


class RiskAssessment(BaseModel):
    score: int
    level: RiskLevel
    recommended_action: RecommendedAction
    factors: list[RiskFactor]
    summary: str


def level_for(score: int) -> RiskLevel:
    if score >= CRITICAL_THRESHOLD:
        return RiskLevel.CRITICAL
    if score >= HIGH_THRESHOLD:
        return RiskLevel.HIGH
    if score >= MEDIUM_THRESHOLD:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


class RiskAssessor:
    """Component 02: turns detection findings into one explainable prompt risk score."""

    def assess(self, detection: DetectionResponse) -> RiskAssessment:
        entities = detection.detected_entities
        if not entities:
            return RiskAssessment(
                score=0,
                level=RiskLevel.LOW,
                recommended_action=RecommendedAction.ALLOW,
                factors=[],
                summary="No sensitive data detected.",
            )

        # Count each entity type once at its most confident occurrence, plus a
        # smaller amount for repeats, so ten emails are riskier than one but do
        # not outweigh a private key.
        by_type: dict[str, list[DetectedEntity]] = {}
        for entity in entities:
            by_type.setdefault(entity.entity_type, []).append(entity)

        factors: list[RiskFactor] = []
        for entity_type, group in by_type.items():
            best = max(group, key=lambda item: item.confidence)
            weight = ENTITY_WEIGHTS.get(entity_type, CATEGORY_DEFAULT_WEIGHTS[best.category])
            points = round(weight * best.confidence)
            repeats = len(group) - 1
            if repeats:
                points += min(weight, round(weight * 0.25 * repeats))
            label = entity_type.replace("_", " ").lower()
            reason = f"{label} (confidence {best.confidence:.2f})"
            if repeats:
                reason += f", {len(group)} occurrences"
            factors.append(RiskFactor(entity_type=entity_type, category=best.category, points=points, reason=reason))

        categories = {entity.category for entity in entities}
        if len(categories) > 1:
            bonus = CATEGORY_COMBINATION_BONUS * (len(categories) - 1)
            names = ", ".join(sorted(category.value.lower() for category in categories))
            factors.append(RiskFactor(
                entity_type="CATEGORY_COMBINATION",
                category=sorted(categories)[0],
                points=bonus,
                reason=f"multiple data categories in one prompt ({names})",
            ))

        factors.sort(key=lambda factor: factor.points, reverse=True)
        score = min(100, sum(factor.points for factor in factors))
        level = level_for(score)
        action = RecommendedAction.BLOCK if level == RiskLevel.CRITICAL else RecommendedAction.SANITIZE
        top = factors[0].reason
        return RiskAssessment(
            score=score,
            level=level,
            recommended_action=action,
            factors=factors,
            summary=f"{level.value.title()} risk ({score}/100), driven mainly by {top}.",
        )
