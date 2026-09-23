from __future__ import annotations

import re

from pydantic import BaseModel

from detection_engine.models.entities import Category
from detection_engine.models.response import DetectionResponse

# Categories whose original values may be put back into the model's reply for
# the user who sent them. Credentials and card data are never restored: the
# reply is displayed and may be copied or logged, and the secret has no
# business re-appearing in it.
RESTORABLE_CATEGORIES = {Category.PII}

# A place or company name on its own ("What is the capital of Sri Lanka?") is
# not sensitive; the NER model marks such hits LOW. Replacing them would make
# ordinary questions unreadable, so they are left in place. They still count
# towards the risk score when they appear next to other personal data.
KEEP_WHEN_LOW_RISK = {"LOCATION", "ORGANIZATION"}


class Replacement(BaseModel):
    placeholder: str
    entity_type: str
    category: Category
    risk_level: str
    masked_value: str
    start: int
    end: int
    restorable: bool


class SanitizedPrompt(BaseModel):
    text: str
    replacements: list[Replacement]

    @property
    def changed(self) -> bool:
        return bool(self.replacements)


class PromptSanitizer:
    """Component 02: replaces detected sensitive spans with typed placeholders.

    ``[EMAIL_ADDRESS_1]`` keeps the prompt readable for the model (it still
    knows an email address was there) while removing the value. Repeated
    occurrences of the same value share one placeholder so references stay
    consistent ("send it to [EMAIL_ADDRESS_1] and cc [EMAIL_ADDRESS_1]").
    """

    def sanitize(self, prompt: str, detection: DetectionResponse) -> tuple[SanitizedPrompt, dict[str, str]]:
        """Return the sanitized prompt and a placeholder -> original value vault.

        The vault never leaves the process: it is used to restore PII in the
        model's reply and then discarded with the request.
        """
        spans = sorted(
            (
                entity for entity in detection.detected_entities
                # Document-level findings (source code) describe the whole
                # prompt; they drive risk and policy, not span replacement.
                if entity.category != Category.SOURCE_CODE
                and entity.end > entity.start
                and not (entity.entity_type in KEEP_WHEN_LOW_RISK and entity.risk_level.value == "LOW")
            ),
            key=lambda entity: entity.start,
        )

        counters: dict[str, int] = {}
        by_value: dict[tuple[str, str], str] = {}
        vault: dict[str, str] = {}
        replacements: list[Replacement] = []
        pieces: list[str] = []
        cursor = 0

        for entity in spans:
            if entity.start < cursor:
                continue  # defensive: detection output is already non-overlapping
            original = prompt[entity.start:entity.end]
            key = (entity.entity_type, original)
            placeholder = by_value.get(key)
            if placeholder is None:
                counters[entity.entity_type] = counters.get(entity.entity_type, 0) + 1
                placeholder = f"[{entity.entity_type}_{counters[entity.entity_type]}]"
                by_value[key] = placeholder
                vault[placeholder] = original

            pieces.append(prompt[cursor:entity.start])
            pieces.append(placeholder)
            cursor = entity.end
            replacements.append(Replacement(
                placeholder=placeholder,
                entity_type=entity.entity_type,
                category=entity.category,
                risk_level=entity.risk_level.value,
                masked_value=entity.masked_value,
                start=entity.start,
                end=entity.end,
                restorable=entity.category in RESTORABLE_CATEGORIES,
            ))
        pieces.append(prompt[cursor:])

        return SanitizedPrompt(text="".join(pieces), replacements=replacements), vault

    @staticmethod
    def restore(reply: str, sanitized: SanitizedPrompt, vault: dict[str, str]) -> str:
        """Put restorable (PII) values back into a model reply for the requester."""
        restorable = {item.placeholder for item in sanitized.replacements if item.restorable}
        if not restorable:
            return reply
        pattern = re.compile("|".join(re.escape(placeholder) for placeholder in sorted(restorable, key=len, reverse=True)))
        return pattern.sub(lambda match: vault.get(match.group(0), match.group(0)), reply)
