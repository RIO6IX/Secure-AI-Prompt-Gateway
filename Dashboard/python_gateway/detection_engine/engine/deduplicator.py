from __future__ import annotations

from detection_engine.models.entities import DetectionCandidate, ValidationStatus


SPECIFICITY = {
    "AWS_ACCESS_KEY": 100,
    "GITHUB_TOKEN": 100,
    "GOOGLE_API_KEY": 100,
    "STRIPE_SECRET_KEY": 100,
    "SLACK_TOKEN": 100,
    "CREDIT_CARD_NUMBER": 90,
    "EMAIL_ADDRESS": 80,
    "GENERIC_API_KEY": 40,
    "HIGH_ENTROPY_SECRET": 30,
}
VALIDATION_RANK = {
    ValidationStatus.CHECKSUM_VALID: 5,
    ValidationStatus.FORMAT_VALID: 4,
    ValidationStatus.CONTEXT_CONFIRMED: 3,
    ValidationStatus.NOT_VALIDATED: 2,
    ValidationStatus.FORMAT_INVALID: 1,
    ValidationStatus.CHECKSUM_INVALID: 1,
}


def _score(candidate: DetectionCandidate) -> tuple[int, int, float, int]:
    return (
        VALIDATION_RANK.get(candidate.validation_status, 0),
        SPECIFICITY.get(candidate.entity_type, 50),
        candidate.confidence,
        candidate.end - candidate.start,
    )


def deduplicate(candidates: list[DetectionCandidate]) -> list[DetectionCandidate]:
    ordered = sorted(candidates, key=lambda item: (item.start, -(item.end - item.start)))
    merged: list[DetectionCandidate] = []
    for candidate in ordered:
        match_index: int | None = None
        for index, existing in enumerate(merged):
            overlaps = candidate.start < existing.end and existing.start < candidate.end
            same_span = candidate.start == existing.start and candidate.end == existing.end
            if overlaps or same_span:
                match_index = index
                break
        if match_index is None:
            merged.append(candidate)
            continue
        existing = merged[match_index]
        winner, loser = (candidate, existing) if _score(candidate) > _score(existing) else (existing, candidate)
        methods = list(dict.fromkeys([*winner.detection_methods, *loser.detection_methods]))
        merged[match_index] = winner.model_copy(update={
            "detection_methods": methods,
            "confidence": max(winner.confidence, loser.confidence),
            "context": winner.context or loser.context,
        })
    return merged
