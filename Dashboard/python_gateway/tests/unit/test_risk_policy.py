import json

import pytest

from detection_engine.engine.detection_engine import SensitiveDataDetectionEngine
from detection_engine.models.request import DetectRequest
from prompt_sanitizer import RiskAssessor, RiskLevel, RiskPolicyError, load_risk_policy

ENGINE = SensitiveDataDetectionEngine()
CARD = "card 4539 1488 0343 6467"


def write(tmp_path, data) -> str:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(data) if not isinstance(data, str) else data, encoding="utf-8")
    return str(path)


def test_no_file_means_built_in_defaults() -> None:
    default = RiskAssessor().assess(ENGINE.detect(DetectRequest(prompt=CARD)))
    assert RiskAssessor(load_risk_policy(None)).assess(ENGINE.detect(DetectRequest(prompt=CARD))).score == default.score


def test_policy_file_overrides_only_what_it_names(tmp_path) -> None:
    policy = load_risk_policy(write(tmp_path, {"entity_weights": {"CREDIT_CARD_NUMBER": 100}}))
    assessor = RiskAssessor(policy)

    card = assessor.assess(ENGINE.detect(DetectRequest(prompt=CARD)))
    default_card = RiskAssessor().assess(ENGINE.detect(DetectRequest(prompt=CARD)))
    email = assessor.assess(ENGINE.detect(DetectRequest(prompt="mail nimal@company.lk")))

    # Weights are scaled by detection confidence, so doubling the weight
    # roughly doubles the card's score and lifts it a level.
    assert card.score > default_card.score
    assert card.level == RiskLevel.HIGH and default_card.level == RiskLevel.MEDIUM
    assert email.score == RiskAssessor().assess(ENGINE.detect(DetectRequest(prompt="mail nimal@company.lk"))).score


def test_thresholds_change_the_level(tmp_path) -> None:
    strict = RiskAssessor(load_risk_policy(write(tmp_path, {"thresholds": {"medium": 5, "high": 10, "critical": 20}})))
    assert strict.assess(ENGINE.detect(DetectRequest(prompt="mail nimal@company.lk"))).level == RiskLevel.HIGH


@pytest.mark.parametrize("data, message", [
    ({"entity_weights": {"PASSWORD": 150}}, "between 0 and 100"),
    ({"thresholds": {"medium": 60, "high": 50, "critical": 80}}, "medium < high < critical"),
    ({"unknown_setting": 1}, "unknown_setting"),
    ({"category_defaults": {"NOT_A_CATEGORY": 10}}, "NOT_A_CATEGORY"),
    ("{not json", "not valid JSON"),
])
def test_invalid_policy_files_fail_loudly(tmp_path, data, message: str) -> None:
    with pytest.raises(RiskPolicyError, match=message):
        load_risk_policy(write(tmp_path, data))


def test_missing_policy_file_fails_loudly(tmp_path) -> None:
    with pytest.raises(RiskPolicyError, match="not found"):
        load_risk_policy(str(tmp_path / "missing.json"))
