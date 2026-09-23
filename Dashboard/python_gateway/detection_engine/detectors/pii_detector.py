from __future__ import annotations

import logging

from detection_engine.core.config import settings
from detection_engine.detectors.base import BaseDetector, DetectionContext
from detection_engine.models.entities import Category, DetectionCandidate, DetectionMethod, RiskLevel

LOGGER = logging.getLogger(__name__)


class PiiDetector(BaseDetector):
    name = "pii_ner_detector"

    def __init__(self) -> None:
        self.model_available = False
        self.presidio_available = False
        self._nlp = None
        try:
            import spacy  # type: ignore

            self._nlp = spacy.load(settings.spacy_model)
            self.model_available = True
        except Exception:
            LOGGER.warning("spaCy model unavailable; continuing with regex detectors only")
        try:
            import presidio_analyzer  # noqa: F401  # type: ignore

            self.presidio_available = True
        except Exception:
            self.presidio_available = False

    def detect(self, text: str, context: DetectionContext) -> list[DetectionCandidate]:
        if not self._nlp:
            return []
        doc = self._nlp(text)
        findings: list[DetectionCandidate] = []
        mapping = {
            "PERSON": ("PERSON_NAME", 0.60),
            "GPE": ("LOCATION", 0.55),
            "LOC": ("LOCATION", 0.55),
            "ORG": ("ORGANIZATION", 0.50),
        }
        for entity in doc.ents:
            if entity.label_ not in mapping:
                continue
            # The small spaCy model tags shouted words ("URGENT", "DATABASE") and
            # short acronyms as organisations; those are noise, not PII.
            if entity.label_ == "ORG" and entity.text.isupper() and (len(entity.text) <= 5 or " " not in entity.text):
                continue
            # Names of people, places and organisations are capitalised; an
            # all-lowercase hit ("token", "api") is a tagging error.
            if not any(char.isupper() for char in entity.text):
                continue
            entity_type, confidence = mapping[entity.label_]
            findings.append(DetectionCandidate(
                entity_type=entity_type,
                category=Category.PII,
                start=entity.start_char,
                end=entity.end_char,
                value=entity.text,
                confidence=confidence,
                risk_level=RiskLevel.MEDIUM if entity_type == "PERSON_NAME" else RiskLevel.LOW,
                detection_methods=[DetectionMethod.NER],
                rule_name=f"spacy_{entity.label_.lower()}",
            ))
        return findings
