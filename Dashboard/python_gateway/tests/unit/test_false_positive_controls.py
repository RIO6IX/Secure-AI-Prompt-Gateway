import pytest

from detection_engine.engine.detection_engine import SensitiveDataDetectionEngine
from detection_engine.models.request import DetectRequest
from detection_engine.validators.iban import is_iban_valid
from detection_engine.validators.identifier import is_sri_lankan_nic_format

ENGINE = SensitiveDataDetectionEngine()


def detect_types(prompt: str) -> dict[str, str]:
    result = ENGINE.detect(DetectRequest(prompt=prompt))
    return {entity.entity_type: prompt[entity.start:entity.end] for entity in result.detected_entities}


def test_iban_uses_mod97_checksum() -> None:
    assert is_iban_valid("GB82WEST12345698765432")
    assert is_iban_valid("DE89 3704 0044 0532 0130 00")
    assert not is_iban_valid("GB82WEST12345698765433")


def test_nic_validation_checks_birth_year_and_day_of_year() -> None:
    assert is_sri_lankan_nic_format("199512345678")
    assert is_sri_lankan_nic_format("857541234V")  # day 754 -> female, day 254
    assert not is_sri_lankan_nic_format("123456789012")  # year 1234
    assert not is_sri_lankan_nic_format("199590012345")  # day 900
    assert not is_sri_lankan_nic_format("854001234V")  # day 400


def test_card_span_excludes_trailing_separator() -> None:
    found = detect_types("card 4539 1488 0343 6467 cvv 123")
    assert found["CREDIT_CARD_NUMBER"] == "4539 1488 0343 6467"


@pytest.mark.parametrize("prompt", [
    "Order reference 1234567 was shipped.",
    "Invoice 2024 0512 3345 is due on 2024-05-12.",
    "Order ref 123456789012 shipped",
    "URGENT: the DATABASE migration is CRITICAL",
])
def test_common_business_text_is_not_flagged(prompt: str) -> None:
    assert detect_types(prompt) == {}


@pytest.mark.parametrize("prompt, expected", [
    ("Call me on +94 77 123 4567", "+94 77 123 4567"),
    ("Mobile 0771234567 anytime", "0771234567"),
    ("Office line (011) 234-5678", "(011) 234-5678"),
])
def test_real_phone_numbers_are_detected(prompt: str, expected: str) -> None:
    assert detect_types(prompt).get("PHONE_NUMBER") == expected


def test_swift_requires_context_and_iban_is_detected() -> None:
    found = detect_types("Wire it to IBAN GB82WEST12345698765432, SWIFT code DEUTDEFF")
    assert found["IBAN"] == "GB82WEST12345698765432"
    assert found["SWIFT_BIC"] == "DEUTDEFF"
    assert "IBAN" not in detect_types("Wire it to GB82WEST12345698765433")


def test_openai_project_key_is_detected_as_critical_credential() -> None:
    result = ENGINE.detect(DetectRequest(prompt="Fix login. API key is sk-proj-ABC1234567890secret and nothing else"))
    keys = [entity for entity in result.detected_entities if entity.entity_type == "OPENAI_API_KEY"]

    assert keys
    assert keys[0].risk_level == "CRITICAL"
    assert "ABC1234567890" not in keys[0].masked_value


@pytest.mark.parametrize("prompt, expected", [
    ("the password is: correct-horse-battery", "correct-horse-battery"),
    ("password = 1234", "1234"),
    ("pwd:S3cr3t!", "S3cr3t!"),
    ('DB_PASSWORD="hunter22"', "hunter22"),
    ('{"user": "svc", "password": "Tr0ub4dor&3"}', "Tr0ub4dor&3"),
    ("my passcode is 739104", "739104"),
])
def test_password_value_is_captured_not_the_separator(prompt: str, expected: str) -> None:
    assert detect_types(prompt).get("PASSWORD") == expected


@pytest.mark.parametrize("prompt", [
    "I forgot my password yesterday, how do I reset it?",
    "my password is too short, what are the rules?",
    "The password is wrong again.",
    "your password is not required for SSO",
])
def test_password_prose_is_not_flagged(prompt: str) -> None:
    assert "PASSWORD" not in detect_types(prompt)


@pytest.mark.parametrize("prompt", [
    "clone https://github.com/RIO6IX/Secure-AI-Prompt-Gateway.git and run it",
    "docs at https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage",
    "download https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js",
])
def test_ordinary_urls_are_not_high_entropy_secrets(prompt: str) -> None:
    assert "HIGH_ENTROPY_SECRET" not in detect_types(prompt)


def test_token_inside_url_query_is_still_detected() -> None:
    prompt = "call https://api.example.org/v1/items?token=Zk3qP9rT2wXy7LmN4bVc8HdS"
    assert detect_types(prompt) == {"GENERIC_API_KEY": "Zk3qP9rT2wXy7LmN4bVc8HdS"}


def test_lowercase_words_are_not_named_entities() -> None:
    found = detect_types("paste the token here and the api will respond")
    assert not {"ORGANIZATION", "PERSON_NAME", "LOCATION"} & set(found)
