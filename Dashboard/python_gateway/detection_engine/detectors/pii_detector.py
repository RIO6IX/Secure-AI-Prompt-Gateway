from __future__ import annotations

import logging
from collections.abc import Iterator

from detection_engine.core.config import settings
from detection_engine.detectors.base import BaseDetector, DetectionContext
from detection_engine.models.entities import Category, DetectionCandidate, DetectionMethod, RiskLevel

LOGGER = logging.getLogger(__name__)

# Only named-entity recognition is needed. Loading the tagger, parser,
# attribute ruler and lemmatizer as well roughly doubles the per-prompt cost.
UNUSED_PIPES = ["tagger", "parser", "attribute_ruler", "lemmatizer", "senter"]
# spaCy's cost grows with document length; chunks keep memory flat and let
# nlp.pipe batch the work.
CHUNK_CHARS = 5_000

LABEL_MAPPING = {
    "PERSON": ("PERSON_NAME", 0.60),
    "GPE": ("LOCATION", 0.55),
    "LOC": ("LOCATION", 0.55),
    "ORG": ("ORGANIZATION", 0.50),
}


def chunk_text(text: str, budget: int, size: int = CHUNK_CHARS) -> Iterator[tuple[int, str]]:
    """Yield (offset, chunk) pieces covering at most ``budget`` characters.

    Chunks end at a line break or space where possible so names are not cut
    in half at a chunk boundary.
    """
    limit = min(len(text), budget)
    offset = 0
    while offset < limit:
        end = min(offset + size, limit)
        if end < limit:
            cut = max(text.rfind("\n", offset, end), text.rfind(" ", offset, end))
            if cut > offset:
                end = cut + 1
        yield offset, text[offset:end]
        offset = end


class PiiDetector(BaseDetector):
    name = "pii_ner_detector"

    def __init__(self) -> None:
        self.model_available = False
        self.presidio_available = False
        self._nlp = None
        try:
            import spacy  # type: ignore

            self._nlp = spacy.load(settings.spacy_model, exclude=UNUSED_PIPES)
            self.model_available = True
        except Exception:
            LOGGER.warning("spaCy model unavailable; continuing with regex detectors only")
        try:
            import presidio_analyzer  # noqa: F401  # type: ignore

            self.presidio_available = True
        except Exception:
            self.presidio_available = False

    @staticmethod
    def _ambiguous_single_name(entity) -> bool:
        """One-word PERSON hits that are usually not names.

        The small model tags acronyms ("NIC") and ordinary words that are
        capitalised only because they start a sentence ("Email the report")
        as people. Multi-word names and one-word names mid-sentence are kept.
        """
        if entity.text.isupper():
            return True
        doc = entity.doc
        before = doc.text[:entity.start_char].rstrip()
        return not before or before[-1] in ".!?:\n"

    def detect(self, text: str, context: DetectionContext) -> list[DetectionCandidate]:
        if not self._nlp:
            return []
        budget = settings.ner_max_chars
        if len(text) > budget:
            # Regex, checksum and entropy rules still scan the whole prompt;
            # only free-text name/place recognition is capped.
            context.warnings.append(
                f"Named-entity recognition covered the first {budget} of {len(text)} characters."
            )

        chunks = list(chunk_text(text, budget))
        findings: list[DetectionCandidate] = []
        for (offset, _), doc in zip(chunks, self._nlp.pipe(chunk for _, chunk in chunks)):
            for entity in doc.ents:
                if entity.label_ not in LABEL_MAPPING:
                    continue
                # The small spaCy model tags shouted words ("URGENT", "DATABASE") and
                # short acronyms as organisations; those are noise, not PII.
                if entity.label_ == "ORG" and entity.text.isupper() and (len(entity.text) <= 5 or " " not in entity.text):
                    continue
                # Names of people, places and organisations are capitalised; an
                # all-lowercase hit ("token", "api") is a tagging error.
                if not any(char.isupper() for char in entity.text):
                    continue
                if entity.label_ == "PERSON" and len(entity) == 1 and self._ambiguous_single_name(entity):
                    continue
                # Personal names do not contain digits; "Zk3qP9rT..." is a token.
                if entity.label_ == "PERSON" and any(char.isdigit() for char in entity.text):
                    continue
                entity_type, confidence = LABEL_MAPPING[entity.label_]
                findings.append(DetectionCandidate(
                    entity_type=entity_type,
                    category=Category.PII,
                    start=offset + entity.start_char,
                    end=offset + entity.end_char,
                    value=entity.text,
                    confidence=confidence,
                    risk_level=RiskLevel.MEDIUM if entity_type == "PERSON_NAME" else RiskLevel.LOW,
                    detection_methods=[DetectionMethod.NER],
                    rule_name=f"spacy_{entity.label_.lower()}",
                ))
        return findings
