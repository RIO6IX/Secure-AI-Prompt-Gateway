"""Masked previews must identify a value without disclosing it."""

import pytest

from detection_engine.engine.masking import mask_value

SECRET = "Q7wErT9yUi0pAs4dFg2hJk6lZx8cVb3nMq5W"


@pytest.mark.parametrize("entity_type, value, expected", [
    ("PASSWORD", "Sup3rS3cretPassw0rd!", "********"),
    ("PASSWORD", "abc", "********"),
    ("CVV", "391", "********"),
    ("GITHUB_TOKEN", "ghp_" + SECRET, "ghp_********...Mq5W"),
    ("OPENAI_API_KEY", "sk-proj-" + SECRET, "sk-proj-********...Mq5W"),
    ("AWS_ACCESS_KEY", "AKIAZ7Q2WJ5K3LMNOPQR", "AKIA********...OPQR"),
    ("GENERIC_API_KEY", "shortsecret1", "********"),
    ("GENERIC_API_KEY", SECRET, "********...Mq5W"),
    ("JWT_TOKEN", "eyJhbGciOiJIUzI1NiJ9.e30.abc", "eyJ********"),
    ("DATABASE_CONNECTION_STRING", "postgres://admin:Wint3r@db.internal:5432/pay", "postgres://****:****@db.internal:5432/pay"),
    ("URL_WITH_CREDENTIALS", "https://deploy:Hunt3r@git.acme.lk/r.git", "https://****:****@git.acme.lk/r.git"),
    ("CREDIT_CARD_NUMBER", "4539 1488 0343 6467", "**** **** **** 6467"),
    ("IBAN", "GB82WEST12345698765432", "GB82 **** **** 5432"),
    ("BANK_ACCOUNT_NUMBER", "8001234567", "******4567"),
    ("EMAIL_ADDRESS", "nimal.perera@company.lk", "n***@company.lk"),
    ("PHONE_NUMBER", "+94 77 123 4567", "*********67"),
    ("SRI_LANKAN_NIC", "912345678v", "*******78v"),
    ("PASSPORT_NUMBER", "N1234567", "N*****67"),
    ("PERSON_NAME", "Kamal Perera", "K. P."),
    ("IP_ADDRESS", "10.20.30.40", "10.20.*.*"),
    ("STREET_ADDRESS", "No. 25, Galle Road, Colombo 03", "********"),
    ("DATE_OF_BIRTH", "1995-03-14", "********"),
])
def test_mask_policy(entity_type: str, value: str, expected: str) -> None:
    assert mask_value(entity_type, value) == expected


@pytest.mark.parametrize("entity_type, value", [
    ("PASSWORD", "Sup3rS3cretPassw0rd!"),
    ("GITHUB_TOKEN", "ghp_" + SECRET),
    ("GENERIC_API_KEY", SECRET),
    ("DATABASE_CONNECTION_STRING", "postgres://admin:Wint3rIsC0ming@db:5432/x"),
])
def test_secret_preview_reveals_at_most_four_characters(entity_type: str, value: str) -> None:
    preview = mask_value(entity_type, value)
    secret_part = value.split(":")[2].split("@")[0] if "://" in value else value
    leaked = [secret_part[i:i + 5] for i in range(len(secret_part) - 4) if secret_part[i:i + 5] in preview]
    assert not leaked, leaked


def test_private_key_preview_keeps_only_the_header() -> None:
    block = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK\nabc\n-----END RSA PRIVATE KEY-----"
    assert mask_value("PEM_PRIVATE_KEY", block) == "-----BEGIN RSA PRIVATE KEY----- [2 lines redacted]"
