import dataclasses

import pytest

from detection_engine.core.config import settings
from detection_engine.detectors import pii_detector
from detection_engine.detectors.pii_detector import chunk_text
from detection_engine.engine.detection_engine import SensitiveDataDetectionEngine
from detection_engine.models.request import DetectRequest

ENGINE = SensitiveDataDetectionEngine()
pytestmark = pytest.mark.skipif(not ENGINE.ner_available, reason="spaCy model not installed")


def test_chunks_cover_budget_and_break_on_whitespace() -> None:
    text = "word " * 3000
    chunks = list(chunk_text(text, budget=12_000, size=5_000))

    assert "".join(chunk for _, chunk in chunks) == text[:12_000]
    assert all(chunk.endswith(" ") for _, chunk in chunks[:-1])
    assert [offset for offset, _ in chunks] == sorted(offset for offset, _ in chunks)


def test_names_in_later_chunks_have_correct_offsets() -> None:
    filler = "The quarterly report covers routine operations. " * 150  # > one chunk
    prompt = filler + "Please call Kamal Perera tomorrow."
    result = ENGINE.detect(DetectRequest(prompt=prompt))
    names = [prompt[entity.start:entity.end] for entity in result.detected_entities if entity.entity_type == "PERSON_NAME"]

    assert "Kamal Perera" in names
    assert result.warnings == []


def test_ner_cap_is_reported_but_secrets_beyond_it_are_still_found(monkeypatch) -> None:
    monkeypatch.setattr(pii_detector, "settings", dataclasses.replace(settings, ner_max_chars=1_000))
    prompt = "Routine status update without anything unusual. " * 60 + "password = Sup3rS3cret!"
    result = ENGINE.detect(DetectRequest(prompt=prompt))

    assert "PASSWORD" in {entity.entity_type for entity in result.detected_entities}
    assert result.warnings and "first 1000" in result.warnings[0]
