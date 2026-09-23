from __future__ import annotations

from detection_engine.models.entities import Category, DetectionCandidate, ValidationStatus


SPECIFICITY = {
    "AWS_ACCESS_KEY": 100,
    "OPENAI_API_KEY": 100,
    "AWS_SECRET_ACCESS_KEY": 100,
    "ANTHROPIC_API_KEY": 100,
    "HUGGINGFACE_TOKEN": 100,
    "AZURE_STORAGE_KEY": 100,
    "GCP_SERVICE_ACCOUNT_KEY": 100,
    "SENDGRID_API_KEY": 100,
    "NPM_TOKEN": 100,
    "SLACK_WEBHOOK": 100,
    "TELEGRAM_BOT_TOKEN": 100,
    "GITHUB_TOKEN": 100,
    "GITLAB_TOKEN": 100,
    "GOOGLE_API_KEY": 100,
    "STRIPE_SECRET_KEY": 100,
    "SLACK_TOKEN": 100,
    "SSH_PRIVATE_KEY": 100,
    "PEM_PRIVATE_KEY": 100,
    "PGP_PRIVATE_KEY": 100,
    "DATABASE_CONNECTION_STRING": 95,
    "URL_WITH_CREDENTIALS": 95,
    "CREDIT_CARD_NUMBER": 90,
    "IBAN": 90,
    "PASSWORD": 85,
    "BEARER_TOKEN": 85,
    "JWT_TOKEN": 85,
    "EMAIL_ADDRESS": 80,
    "SRI_LANKAN_NIC": 70,
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
        SPECIFICITY.get(candidate.entity_type, 50),
        VALIDATION_RANK.get(candidate.validation_status, 0),
        candidate.confidence,
        candidate.end - candidate.start,
    )


def _is_document_level(candidate: DetectionCandidate) -> bool:
    # Source-code findings describe the prompt as a whole rather than a single
    # value, so they must never compete with (or swallow) span-level entities.
    return candidate.category == Category.SOURCE_CODE


def _merge(winner: DetectionCandidate, loser: DetectionCandidate) -> DetectionCandidate:
    methods = list(dict.fromkeys([*winner.detection_methods, *loser.detection_methods]))
    return winner.model_copy(update={
        "detection_methods": methods,
        "confidence": max(winner.confidence, loser.confidence),
        "context": winner.context or loser.context,
    })


def deduplicate(candidates: list[DetectionCandidate]) -> list[DetectionCandidate]:
    document_level = [candidate for candidate in candidates if _is_document_level(candidate)]
    span_level = [candidate for candidate in candidates if not _is_document_level(candidate)]

    ordered = sorted(span_level, key=lambda item: (item.start, -(item.end - item.start)))
    merged: list[DetectionCandidate] = []
    for candidate in ordered:
        overlapping = [
            index for index, existing in enumerate(merged)
            if candidate.start < existing.end and existing.start < candidate.end
        ]
        if not overlapping:
            merged.append(candidate)
            continue
        # A candidate can bridge several already-kept spans; fold all of them
        # into a single winner so the output never contains overlapping spans.
        group = [merged[index] for index in overlapping] + [candidate]
        winner = max(group, key=_score)
        for other in group:
            if other is not winner:
                winner = _merge(winner, other)
        for index in reversed(overlapping):
            merged.pop(index)
        merged.append(winner)
        merged.sort(key=lambda item: item.start)

    best_document = max(document_level, key=lambda item: item.confidence, default=None)
    if best_document is not None:
        merged.append(best_document)
    return merged
