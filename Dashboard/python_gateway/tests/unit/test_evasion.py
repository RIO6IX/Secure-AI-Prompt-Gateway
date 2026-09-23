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


KEY_BODY = (
    "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun\n"
    "VTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxK\n"
    "q2eXq4pN9oA7m3cG1fYdLkZ0Q8vR6sT2uWxYzA1bC3dE5fG7hI9jK0lM2nO4pQ6r\n"
)


@pytest.mark.parametrize("kind, entity_type", [
    ("RSA PRIVATE KEY", "PEM_PRIVATE_KEY"),
    ("PRIVATE KEY", "PEM_PRIVATE_KEY"),
    ("ENCRYPTED PRIVATE KEY", "PEM_PRIVATE_KEY"),
    ("OPENSSH PRIVATE KEY", "SSH_PRIVATE_KEY"),
    ("PGP PRIVATE KEY BLOCK", "PGP_PRIVATE_KEY"),
])
def test_private_key_finding_covers_the_whole_block(kind: str, entity_type: str) -> None:
    block = f"-----BEGIN {kind}-----\n{KEY_BODY}-----END {kind}-----"
    prompt = f"Why does this fail?\n{block}\nThanks"
    spans = found(prompt)

    assert spans[entity_type] == block
    assert "HIGH_ENTROPY_SECRET" not in spans


def test_truncated_private_key_is_covered_to_the_end() -> None:
    prompt = f"-----BEGIN RSA PRIVATE KEY-----\n{KEY_BODY}"
    assert found(prompt)["PEM_PRIVATE_KEY"] == prompt
