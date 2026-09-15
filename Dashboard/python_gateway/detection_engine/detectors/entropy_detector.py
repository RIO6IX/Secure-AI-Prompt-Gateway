from __future__ import annotations

import math
import re
from collections import Counter

from detection_engine.core.config import settings
from detection_engine.detectors.base import BaseDetector, DetectionContext
from detection_engine.models.entities import Category, DetectionCandidate, DetectionMethod, RiskLevel
from detection_engine.rules.allowlists import is_placeholder

TOKEN_RE = re.compile(r"\b[A-Za-z0-9+/=_~.-]{16,256}\b")
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
SHA_RE = re.compile(r"^[0-9a-fA-F]{32,128}$")


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


class EntropyDetector(BaseDetector):
    name = "entropy_detector"

    def detect(self, text: str, context: DetectionContext) -> list[DetectionCandidate]:
        findings: list[DetectionCandidate] = []
        for match in TOKEN_RE.finditer(text):
            value = match.group(0)
            if not settings.entropy_min_length <= len(value) <= settings.entropy_max_length:
                continue
            if is_placeholder(value) or UUID_RE.fullmatch(value) or SHA_RE.fullmatch(value):
                continue
            entropy = shannon_entropy(value)
            if entropy < settings.entropy_threshold:
                continue
            start, end = match.span()
            window = text[max(0, start - 60): min(len(text), end + 60)].lower()
            secret_context = any(word in window for word in ("secret", "token", "password", "credential", "api_key", "api key", "auth", "bearer", "private_key"))
            confidence = min(0.88, 0.46 + ((entropy - settings.entropy_threshold) * 0.10) + (0.20 if secret_context else 0.0))
            findings.append(DetectionCandidate(
                entity_type="HIGH_ENTROPY_SECRET",
                category=Category.CREDENTIAL,
                start=start,
                end=end,
                value=value,
                confidence=confidence,
                risk_level=RiskLevel.HIGH if secret_context else RiskLevel.MEDIUM,
                detection_methods=[DetectionMethod.ENTROPY],
                rule_name="high_entropy_candidate",
                metadata={"entropy": round(entropy, 3), "secret_context": secret_context},
            ))
        return findings
