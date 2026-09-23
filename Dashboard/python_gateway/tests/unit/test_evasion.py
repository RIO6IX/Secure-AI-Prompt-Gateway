import pytest

from detection_engine.engine.detection_engine import SensitiveDataDetectionEngine
from detection_engine.models.request import DetectRequest

ENGINE = SensitiveDataDetectionEngine()


def found(prompt: str) -> dict[str, str]:
    result = ENGINE.detect(DetectRequest(prompt=prompt))
    return {entity.entity_type: prompt[entity.start:entity.end] for entity in result.detected_entities}


@pytest.mark.parametrize("separator", ["​", "‌", "‍", "⁠", "﻿", "­"])
def test_invisible_characters_do_not_hide_a_key(separator: str) -> None:
    prompt = f"key AKIA{separator}Z7Q2WJ5K3LMNOPQR please"
    spans = found(prompt)

    assert "AWS_ACCESS_KEY" in spans
    # The reported span covers the original text, including the hidden character,
    # so redacting it removes the whole key.
    assert spans["AWS_ACCESS_KEY"] == f"AKIA{separator}Z7Q2WJ5K3LMNOPQR"


def test_fullwidth_digits_are_normalised_before_matching() -> None:
    prompt = "card ４５３９ 1488 0343 6467"
    assert "CREDIT_CARD_NUMBER" in found(prompt)


def test_nul_bytes_do_not_shift_spans() -> None:
    prompt = "a\x00b email nimal@company.lk"
    assert found(prompt)["EMAIL_ADDRESS"] == "nimal@company.lk"
