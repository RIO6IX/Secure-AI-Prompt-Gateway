import pytest

from detection_engine.engine.detection_engine import SensitiveDataDetectionEngine
from detection_engine.models.request import DetectRequest
from prompt_sanitizer import PromptSanitizer, ResponseGuard

ENGINE = SensitiveDataDetectionEngine()
SANITIZER = PromptSanitizer()
GUARD = ResponseGuard(lambda text: ENGINE.detect(DetectRequest(prompt=text)))
PROMPT = "Reply to nimal.perera@company.lk about card 4539 1488 0343 6467"


def sanitized():
    detection = ENGINE.detect(DetectRequest(prompt=PROMPT))
    return SANITIZER.sanitize(PROMPT, detection)[0]


@pytest.mark.parametrize("reply, expected", [
    ("We emailed [EMAIL_ADDRESS_1].", "We emailed n***@company.lk."),
    ("We emailed [Email_Address_1].", "We emailed n***@company.lk."),
    ("sent to EMAIL ADDRESS 1 (card [credit_card_number_1])", "sent to n***@company.lk (card **** **** **** 6467)"),
    ("see (EMAIL_ADDRESS_1)", "see n***@company.lk"),
])
def test_placeholders_in_any_spelling_become_masked_previews(reply: str, expected: str) -> None:
    assert GUARD.guard(reply, sanitized()).text == expected


def test_placeholder_number_must_match_exactly() -> None:
    assert GUARD.guard("ids EMAIL_ADDRESS_10 and x", sanitized()).text == "ids EMAIL_ADDRESS_10 and x"


def test_model_generated_secrets_are_masked() -> None:
    result = GUARD.guard("Try password = hunter22 and key AKIAZ7Q2WJ5K3LMNOPQR", sanitized())
    assert "hunter22" not in result.text and "AKIAZ7Q2WJ5K3LMNOPQR" not in result.text
    assert result.findings_masked == 2


def test_clean_reply_and_place_names_are_unchanged() -> None:
    reply = "The capital of Sri Lanka is Colombo."
    result = GUARD.guard(reply, sanitized())
    assert result.text == reply
    assert result.total_masked == 0


def test_kept_values_are_not_masked_again() -> None:
    reply = "Hello nimal.perera@company.lk"
    result = GUARD.guard(reply, sanitized(), keep_values=frozenset({"nimal.perera@company.lk"}))
    assert result.text == reply
