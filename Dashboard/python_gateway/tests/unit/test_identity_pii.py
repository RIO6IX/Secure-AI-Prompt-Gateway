from datetime import date

import pytest

from detection_engine.engine.detection_engine import SensitiveDataDetectionEngine
from detection_engine.models.request import DetectRequest
from detection_engine.validators.date_of_birth import is_plausible_birth_date, parse_birth_date

ENGINE = SensitiveDataDetectionEngine()


def found(prompt: str) -> dict[str, str]:
    result = ENGINE.detect(DetectRequest(prompt=prompt))
    return {entity.entity_type: prompt[entity.start:entity.end] for entity in result.detected_entities}


@pytest.mark.parametrize("prompt, expected", [
    ("My passport number is N1234567", "N1234567"),
    ("Passport No: N7654321, expires 2030", "N7654321"),
    ("passport# AB1234567", "AB1234567"),
])
def test_passport_numbers_are_detected_with_context(prompt: str, expected: str) -> None:
    assert found(prompt).get("PASSPORT_NUMBER") == expected


def test_passport_shaped_code_without_context_is_ignored() -> None:
    assert "PASSPORT_NUMBER" not in found("Order N1234567 shipped today")


@pytest.mark.parametrize("prompt, expected", [
    ("Customer date of birth: 1995-03-14", "1995-03-14"),
    ("DOB 14/03/1995, NIC pending", "14/03/1995"),
    ("She was born on 14 March 1995 in Kandy", "14 March 1995"),
])
def test_dates_of_birth_are_detected_with_context(prompt: str, expected: str) -> None:
    assert found(prompt).get("DATE_OF_BIRTH") == expected


@pytest.mark.parametrize("prompt", [
    "Release date: 2024-05-12",  # no birth context
    "date of birth: 2099-01-01",  # in the future
    "date of birth: 1995-02-30",  # not a real date
    "date of birth: 1850-01-01",  # older than any living person
])
def test_implausible_or_uncontextual_dates_are_ignored(prompt: str) -> None:
    assert "DATE_OF_BIRTH" not in found(prompt)


def test_birth_date_parser_formats() -> None:
    assert parse_birth_date("1995-03-14") == date(1995, 3, 14)
    assert parse_birth_date("14.03.1995") == date(1995, 3, 14)
    assert parse_birth_date("14 Sept 1995") == date(1995, 9, 14)
    assert not is_plausible_birth_date("31/04/1995")


def test_card_numbers_separated_by_dots_are_detected() -> None:
    assert found("card 4539.1488.0343.6467 please refund")["CREDIT_CARD_NUMBER"] == "4539.1488.0343.6467"


def test_dotted_version_numbers_are_not_cards() -> None:
    assert found("upgrade to 1.2.3.4 then 10.0.0.12").get("CREDIT_CARD_NUMBER") is None
