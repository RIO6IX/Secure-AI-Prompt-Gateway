from __future__ import annotations

from detection_engine.models.entities import DetectionCandidate, DetectionMethod, ValidationStatus
from detection_engine.rules.allowlists import NEGATIVE_CONTEXT, is_placeholder
from detection_engine.rules.context_keywords import POSITIVE_CONTEXT
from detection_engine.rules.keyword_match import keywords_in


VALIDATED_CONFIDENCE_FLOOR = 0.50


def clamp(value: float) -> float:
    return max(0.0, min(1.0, value))


def context_window(text: str, start: int, end: int, radius: int = 80) -> str:
    return text[max(0, start - radius): min(len(text), end + radius)].lower()


def enhance_candidate(candidate: DetectionCandidate, text: str) -> DetectionCandidate:
    window = context_window(text, candidate.start, candidate.end)
    category_words = POSITIVE_CONTEXT.get(candidate.category.value, set())
    positive = sorted(keywords_in(window, category_words))
    negative_hits = keywords_in(window, NEGATIVE_CONTEXT)

    validation_adjustment = 0.0
    if candidate.validation_status in {ValidationStatus.FORMAT_VALID, ValidationStatus.CHECKSUM_VALID, ValidationStatus.CONTEXT_CONFIRMED}:
        validation_adjustment = 0.12
    elif candidate.validation_status in {ValidationStatus.FORMAT_INVALID, ValidationStatus.CHECKSUM_INVALID}:
        validation_adjustment = -0.35

    context_adjustment = min(0.12, 0.04 * len(positive))
    penalty = min(0.25, 0.08 * len(negative_hits))
    placeholder_penalty = 0.25 if is_placeholder(candidate.value) else 0.0
    corroboration = 0.05 if len(set(candidate.detection_methods)) > 1 else 0.0
    confidence = clamp(candidate.confidence + validation_adjustment + context_adjustment + corroboration - penalty - placeholder_penalty)
    if candidate.validation_status in {ValidationStatus.CHECKSUM_VALID, ValidationStatus.FORMAT_VALID}:
        # "test"/"example" nearby lowers confidence, but a value that passed a
        # deterministic check is still reported: a Luhn-valid PAN must never
        # silently fall under the reporting threshold.
        confidence = max(confidence, VALIDATED_CONFIDENCE_FLOOR)

    methods = list(dict.fromkeys(candidate.detection_methods))
    context_bits: list[str] = []
    if positive:
        context_bits.append(f"Detected near {', '.join(positive[:3])}.")
        if DetectionMethod.CONTEXT not in methods:
            methods.append(DetectionMethod.CONTEXT)
    if negative_hits or placeholder_penalty:
        context_bits.append("Known test, documentation, or placeholder context reduced risk.")
    if not context_bits:
        context_bits.append("Detected by local pattern or model without exposing the raw value.")

    return candidate.model_copy(update={
        "confidence": confidence,
        "detection_methods": methods,
        "context": " ".join(context_bits),
    })
