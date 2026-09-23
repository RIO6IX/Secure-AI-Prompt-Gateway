"""Vendor credential formats, mirroring the rule sets of Gitleaks/TruffleHog.

Every value is synthetic: built from a fixed alphabet to the documented
length, so it has the right shape but belongs to no real account.
"""

import pytest

from detection_engine.engine.detection_engine import SensitiveDataDetectionEngine
from detection_engine.models.request import DetectRequest

ENGINE = SensitiveDataDetectionEngine()
ALNUM = "Q7wErT9yUi0pAs4dFg2hJk6lZx8cVb3nMq5W"


def synthetic(length: int, alphabet: str = ALNUM) -> str:
    return (alphabet * (length // len(alphabet) + 1))[:length]


def detect(prompt: str):
    return ENGINE.detect(DetectRequest(prompt=prompt)).detected_entities


CASES = [
    ("AWS_SECRET_ACCESS_KEY", "aws_secret_access_key = {}", synthetic(36) + "a/B+"),
    ("ANTHROPIC_API_KEY", "use {} for claude", "sk-ant-api03-" + synthetic(40)),
    ("HUGGINGFACE_TOKEN", "HF token {}", "hf_" + synthetic(34)),
    ("SENDGRID_API_KEY", "mail key {}", "SG." + synthetic(22) + "." + synthetic(43)),
    ("NPM_TOKEN", "//registry.npmjs.org/:_authToken={}", "npm_" + synthetic(36)),
    ("SLACK_WEBHOOK", "post to {}", "https://hooks.slack.com/services/T0ABC1234/B0DEF5678/" + synthetic(24)),
    ("TELEGRAM_BOT_TOKEN", "bot {}", "123456789:AA" + synthetic(33)),
    ("GCP_SERVICE_ACCOUNT_KEY", '{{"type": "service_account", "private_key_id": "{}"}}', synthetic(40, "0123456789abcdef")),
    ("AZURE_STORAGE_KEY", "DefaultEndpointsProtocol=https;AccountName=acme;AccountKey={};EndpointSuffix=core.windows.net", synthetic(86) + "=="),
]


@pytest.mark.parametrize("entity_type, template, secret", CASES, ids=[case[0] for case in CASES])
def test_vendor_secret_is_detected_critical_and_fully_covered(entity_type: str, template: str, secret: str) -> None:
    prompt = template.format(secret)
    matches = [entity for entity in detect(prompt) if entity.entity_type == entity_type]

    assert matches, f"{entity_type} not detected"
    entity = matches[0]
    assert entity.risk_level == "CRITICAL"
    assert secret in prompt[entity.start:entity.end]
    assert secret not in entity.masked_value


def test_anthropic_key_is_not_misclassified_as_openai() -> None:
    types = {entity.entity_type for entity in detect("key sk-ant-api03-" + synthetic(40))}
    assert types == {"ANTHROPIC_API_KEY"}
