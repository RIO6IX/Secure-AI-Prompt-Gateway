"""Output-side protection for model replies (Component 02).

The prompt is sanitized before it reaches the model, but the reply still
needs checking before it is shown or logged:

1. The model repeats placeholders such as ``[EMAIL_ADDRESS_1]``, often
   rewritten (``[Email_Address_1]``, ``EMAIL ADDRESS 1``). Each one is
   replaced with the masked preview of the original value
   (``n***@company.lk``), so the reply stays readable without showing the
   real value.
2. The model can produce sensitive data itself: hallucinated keys, card
   numbers from training data, or values the user asked it to invent.
   The reply is scanned with the detection engine and every finding is
   masked the same way.

OWASP lists "sensitive information disclosure" in LLM output as a top
risk (LLM02), so the reply is treated as untrusted data.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from pydantic import BaseModel

from detection_engine.models.response import DetectionResponse
from prompt_sanitizer.sanitizer import SanitizedPrompt

# Context-only findings stay readable in replies ("the Colombo office").
KEEP_IN_REPLY = {"LOCATION", "ORGANIZATION", "SOURCE_CODE", "PRIVATE_SOURCE_CODE"}
PLACEHOLDER_RE = re.compile(r"^\[([A-Z0-9_]+)_(\d+)\]$")


class GuardedReply(BaseModel):
    text: str
    placeholders_masked: int
    findings_masked: int
    finding_types: list[str]

    @property
    def total_masked(self) -> int:
        return self.placeholders_masked + self.findings_masked


def _loose_placeholder_pattern(placeholder: str) -> re.Pattern[str] | None:
    match = PLACEHOLDER_RE.match(placeholder)
    if not match:
        return None
    words = [re.escape(word) for word in match.group(1).split("_")]
    body = r"[_ -]?".join(words) + r"[_ -]?" + match.group(2) + r"(?!\d)"
    # Any case; brackets and the spaces inside them are consumed only when a
    # bracket pair is present, so "to EMAIL ADDRESS 1 (card" keeps its spaces.
    # The number must not continue (_1 must not match _10).
    return re.compile(rf"(?i)(?:\[\s*{body}\s*\]|\(\s*{body}\s*\)|(?<![A-Za-z0-9_]){body})")


class ResponseGuard:
    """Masks placeholders and newly generated sensitive values in a reply."""

    def __init__(self, detect: Callable[[str], DetectionResponse]) -> None:
        self._detect = detect

    def guard(
        self,
        reply: str,
        sanitized: SanitizedPrompt,
        keep_values: frozenset[str] = frozenset(),
        known_placeholders: dict[str, str] | None = None,
    ) -> GuardedReply:
        """Mask placeholders and sensitive values in ``reply``.

        ``keep_values`` are the requester's own values that were deliberately
        restored (REPLY_PII_MODE=restore); they are not masked again.
        """
        text = reply
        placeholders_masked = 0
        # Placeholders from earlier turns of the conversation, then this prompt's.
        seen: dict[str, str] = dict(known_placeholders or {})
        for item in sanitized.replacements:
            seen.setdefault(item.placeholder, item.masked_value)
        for placeholder in sorted(seen, key=len, reverse=True):
            pattern = _loose_placeholder_pattern(placeholder)
            if pattern is None:
                continue
            text, count = pattern.subn(seen[placeholder], text)
            placeholders_masked += count

        findings_masked = 0
        finding_types: list[str] = []
        if text.strip():
            detection = self._detect(text)
            entities = [
                entity for entity in detection.detected_entities
                if entity.entity_type not in KEEP_IN_REPLY and entity.end > entity.start
                and text[entity.start:entity.end] not in keep_values
            ]
            for entity in sorted(entities, key=lambda item: item.start, reverse=True):
                text = text[:entity.start] + entity.masked_value + text[entity.end:]
                findings_masked += 1
                finding_types.append(entity.entity_type)

        return GuardedReply(
            text=text,
            placeholders_masked=placeholders_masked,
            findings_masked=findings_masked,
            finding_types=sorted(set(finding_types)),
        )
