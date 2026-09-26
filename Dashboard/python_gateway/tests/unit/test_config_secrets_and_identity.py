"""Secrets in config/env/header form, bank accounts, addresses and names."""

import pytest

from detection_engine.engine.detection_engine import SensitiveDataDetectionEngine
from detection_engine.models.request import DetectRequest

ENGINE = SensitiveDataDetectionEngine()
TOKEN = "Q7wErT9yUi0pAs4dFg2hJk6lZx8c"


def found(prompt: str) -> dict[str, str]:
    result = ENGINE.detect(DetectRequest(prompt=prompt))
    return {entity.entity_type: prompt[entity.start:entity.end] for entity in result.detected_entities}


@pytest.mark.parametrize("prompt, value", [
    ("SECRET_KEY=django-insecure-8f#k2@x!q9z$w7v6u5\nDEBUG=True", "django-insecure-8f#k2@x!q9z$w7v6u5"),
    (f"client_secret={TOKEN}", TOKEN),
    (f"api_key: '{TOKEN}'", TOKEN),
    (f"curl -H 'x-api-key: {TOKEN}' https://api.acme.lk", TOKEN),
    (f"https://api.acme.lk/v1?api_key={TOKEN}&page=2", TOKEN),
    (f'{{"auth_token": "{TOKEN}"}}', TOKEN),
    (f"export ENCRYPTION_KEY={TOKEN}", TOKEN),
])
def test_secret_assignments_capture_the_whole_value_only(prompt: str, value: str) -> None:
    assert found(prompt).get("GENERIC_API_KEY") == value


@pytest.mark.parametrize("prompt", [
    "API_KEY=${API_KEY}",
    "token: <your-token-here>",
    "SECRET=changeme",
    "client_secret=xxxxxxxxxxxx",
    "set token = {{ secrets.DEPLOY_TOKEN }}",
    "The secret is to keep it simple.",
])
def test_template_and_prose_values_are_not_secrets(prompt: str) -> None:
    assert "GENERIC_API_KEY" not in found(prompt)


def test_basic_auth_header_is_decoded_and_verified() -> None:
    assert found("Authorization: Basic YWRtaW46U3VwM3JTM2NyZXQh")["BASIC_AUTH_CREDENTIALS"] == "YWRtaW46U3VwM3JTM2NyZXQh"
    # base64 without a user:password pair is not Basic credentials
    assert "BASIC_AUTH_CREDENTIALS" not in found("Basic aGVsbG8gd29ybGQ=")


def test_stripe_webhook_secret_is_critical() -> None:
    result = ENGINE.detect(DetectRequest(prompt="STRIPE_WEBHOOK_SECRET=whsec_" + TOKEN))
    entity = next(e for e in result.detected_entities if e.entity_type == "STRIPE_WEBHOOK_SECRET")
    assert entity.risk_level == "CRITICAL"


@pytest.mark.parametrize("prompt, value", [
    ("Account number 1234567890123 at Commercial Bank", "1234567890123"),
    ("acc no: 8001234567", "8001234567"),
    ("Transfer to A/C 0012-3456-7890", "0012-3456-7890"),
])
def test_bank_account_numbers_need_account_context(prompt: str, value: str) -> None:
    spans = found(prompt)
    assert spans.get("BANK_ACCOUNT_NUMBER") == value
    assert "PHONE_NUMBER" not in spans


@pytest.mark.parametrize("prompt, value", [
    ("My address is No. 25, Galle Road, Colombo 03", "No. 25, Galle Road, Colombo 03"),
    ("Ship to 42/1 Temple Lane, Kandy 20000", "42/1 Temple Lane, Kandy 20000"),
    ("Deliver to 12A Duplication Rd, Colombo 04 today", "12A Duplication Rd, Colombo 04"),
])
def test_street_addresses_are_detected(prompt: str, value: str) -> None:
    assert found(prompt).get("STREET_ADDRESS") == value


@pytest.mark.parametrize("prompt", [
    "See chapter 2 Road Map for details",
    "We sold 25 units on the road yesterday",
])
def test_non_addresses_are_ignored(prompt: str) -> None:
    assert "STREET_ADDRESS" not in found(prompt)


def test_honorific_names_including_lowercase_are_found() -> None:
    names = [
        entity for entity in ENGINE.detect(DetectRequest(prompt="Mr. Kamal Perera and ms. nimali silva joined")).detected_entities
        if entity.entity_type == "PERSON_NAME"
    ]
    assert len(names) == 2


def test_sri_lankan_towns_are_not_people() -> None:
    spans = found("Open the account at the branch in Kandy")
    assert "PERSON_NAME" not in spans


@pytest.mark.parametrize("prompt, name", [
    ("Invoice for Kamal Perera", "Kamal Perera"),
    ("Dear Nimali de Silva, thanks", "Nimali de Silva"),
    ("Approved by K. Perera", "K. Perera"),
    ("Signed A.B. Jayawardena", "A.B. Jayawardena"),
    ("Assign to Priya Sivakumar", "Priya Sivakumar"),
    ("Refund Fathima Rizwan", "Fathima Rizwan"),
])
def test_sri_lankan_names_are_detected(prompt: str, name: str) -> None:
    names = [prompt[e.start:e.end] for e in ENGINE.detect(DetectRequest(prompt=prompt)).detected_entities if e.entity_type == "PERSON_NAME"]
    assert name in names


@pytest.mark.parametrize("prompt", [
    "Perera & Sons won the tender",
    "The shop is on Fernando Mawatha",
])
def test_surname_alone_or_after_command_word_is_not_a_person(prompt: str) -> None:
    assert "PERSON_NAME" not in found(prompt)
