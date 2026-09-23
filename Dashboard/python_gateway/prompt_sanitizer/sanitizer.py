from __future__ import annotations

import hashlib
import hmac
import re
import secrets

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


class PseudonymMap:
    """Placeholder assignments that can span several prompts of one conversation.

    The same value must get the same placeholder in every turn, and a new
    value must never reuse a placeholder from an earlier turn; otherwise the
    model would confuse two customers who both appear as [EMAIL_ADDRESS_1].

    Values are looked up by a keyed hash (HMAC-SHA256 with a per-map random
    key), so the map can live for a whole conversation without holding
    plaintext secrets. Plain values are kept only when ``keep_values`` is set
    (REPLY_PII_MODE=restore) and only for restorable PII.
    """

    def __init__(self, keep_values: bool = False) -> None:
        self._key = secrets.token_bytes(32)
        self.keep_values = keep_values
        self._counters: dict[str, int] = {}
        self._by_digest: dict[str, str] = {}
        self.masked: dict[str, str] = {}
        self.values: dict[str, str] = {}

    def _digest(self, entity_type: str, value: str) -> str:
        return hmac.new(self._key, f"{entity_type}\x00{value}".encode("utf-8"), hashlib.sha256).hexdigest()

    def assign(self, entity_type: str, value: str, masked_value: str, restorable: bool, avoid: str) -> str:
        """Placeholder for ``value``: existing one if seen before, else the next free number.

        ``avoid`` is text whose literal placeholders must not be reused (the
        user may have typed "[EMAIL_ADDRESS_1]" themselves).
        """
        digest = self._digest(entity_type, value)
        placeholder = self._by_digest.get(digest)
        if placeholder is None:
            while True:
                self._counters[entity_type] = self._counters.get(entity_type, 0) + 1
                placeholder = f"[{entity_type}_{self._counters[entity_type]}]"
                if placeholder not in avoid and placeholder not in self.masked:
                    break
            self._by_digest[digest] = placeholder
            self.masked[placeholder] = masked_value
        if self.keep_values and restorable:
            self.values[placeholder] = value
        return placeholder

    def copy(self) -> PseudonymMap:
        """Working copy, so a blocked prompt's values can be discarded."""
        clone = PseudonymMap(self.keep_values)
        clone._key = self._key
        clone._counters = dict(self._counters)
        clone._by_digest = dict(self._by_digest)
        clone.masked = dict(self.masked)
        clone.values = dict(self.values)
        return clone


class PromptSanitizer:
    """Component 02: replaces detected sensitive spans with typed placeholders.

    ``[EMAIL_ADDRESS_1]`` keeps the prompt readable for the model (it still
    knows an email address was there) while removing the value. Repeated
    occurrences of the same value share one placeholder so references stay
    consistent ("send it to [EMAIL_ADDRESS_1] and cc [EMAIL_ADDRESS_1]").
    """

    def sanitize(
        self,
        prompt: str,
        detection: DetectionResponse,
        mapping: PseudonymMap | None = None,
    ) -> tuple[SanitizedPrompt, dict[str, str]]:
        """Return the sanitized prompt and a placeholder -> original value vault.

        Pass the conversation's ``mapping`` to keep placeholders consistent
        across turns; without one, numbering starts fresh. The vault covers
        this prompt only, never leaves the process and is used to restore PII
        in the model's reply (REPLY_PII_MODE=restore).
        """
        mapping = mapping if mapping is not None else PseudonymMap()
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

        vault: dict[str, str] = {}
        replacements: list[Replacement] = []
        pieces: list[str] = []
        cursor = 0

        for entity in spans:
            if entity.start < cursor:
                continue  # defensive: detection output is already non-overlapping
            original = prompt[entity.start:entity.end]
            restorable = entity.category in RESTORABLE_CATEGORIES
            # Never reuse a placeholder the user already typed; otherwise
            # restore() would put a real value where their own text was.
            placeholder = mapping.assign(entity.entity_type, original, entity.masked_value, restorable, avoid=prompt)
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
                restorable=restorable,
            ))
        pieces.append(prompt[cursor:])

        return SanitizedPrompt(text="".join(pieces), replacements=replacements), vault

    @staticmethod
    def restore_all(reply: str, vault: dict[str, str]) -> str:
        """Restore every placeholder in ``vault`` (callers pass restorable PII only)."""
        if not vault:
            return reply
        pattern = re.compile("|".join(re.escape(placeholder) for placeholder in sorted(vault, key=len, reverse=True)))
        return pattern.sub(lambda match: vault[match.group(0)], reply)

    @staticmethod
    def restore(reply: str, sanitized: SanitizedPrompt, vault: dict[str, str]) -> str:
        """Put restorable (PII) values back into a model reply for the requester."""
        restorable = {item.placeholder for item in sanitized.replacements if item.restorable}
        if not restorable:
            return reply
        pattern = re.compile("|".join(re.escape(placeholder) for placeholder in sorted(restorable, key=len, reverse=True)))
        return pattern.sub(lambda match: vault.get(match.group(0), match.group(0)), reply)
