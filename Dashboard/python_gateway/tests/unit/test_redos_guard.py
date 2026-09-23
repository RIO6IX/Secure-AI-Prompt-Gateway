"""Worst-case input guard.

Prompts are attacker-controlled, so a regex with catastrophic backtracking
would let one prompt stall a gateway worker (ReDoS). These inputs target
the repetition-heavy rules at the maximum prompt size; each must finish
well inside a request timeout.
"""

import time

import pytest

from detection_engine.core.config import settings
from detection_engine.engine.detection_engine import SensitiveDataDetectionEngine
from detection_engine.models.request import DetectRequest

ENGINE = SensitiveDataDetectionEngine()
BUDGET_SECONDS = 5.0


@pytest.mark.parametrize("unit", [
    "1",
    "1 ",
    "1.",
    "a@",
    "Ab9+/",
    "password is ",
    "-----BEGIN RSA PRIVATE KEY-----\n",
])
def test_adversarial_input_finishes_quickly(unit: str) -> None:
    prompt = (unit * (settings.max_prompt_length // len(unit) + 1))[: settings.max_prompt_length]
    started = time.perf_counter()
    ENGINE.detect(DetectRequest(prompt=prompt))
    assert time.perf_counter() - started < BUDGET_SECONDS
