from detection_engine.engine.detection_engine import SensitiveDataDetectionEngine
from detection_engine.models.request import DetectRequest
from prompt_sanitizer import PromptSanitizer, RecommendedAction, RiskAssessor, RiskLevel

ENGINE = SensitiveDataDetectionEngine()
SANITIZER = PromptSanitizer()
ASSESSOR = RiskAssessor()


def run(prompt: str):
    detection = ENGINE.detect(DetectRequest(prompt=prompt))
    sanitized, vault = SANITIZER.sanitize(prompt, detection)
    return detection, sanitized, vault


def test_values_are_replaced_with_typed_numbered_placeholders() -> None:
    prompt = "Email nimal@company.lk and kamal@company.lk, card 4539 1488 0343 6467"
    _, sanitized, _ = run(prompt)

    assert sanitized.text == "Email [EMAIL_ADDRESS_1] and [EMAIL_ADDRESS_2], card [CREDIT_CARD_NUMBER_1]"
    assert "nimal@company.lk" not in sanitized.text
    assert "4539" not in sanitized.text


def test_repeated_value_reuses_the_same_placeholder() -> None:
    _, sanitized, _ = run("Send it to nimal@company.lk and cc nimal@company.lk")

    assert sanitized.text == "Send it to [EMAIL_ADDRESS_1] and cc [EMAIL_ADDRESS_1]"
    assert len(sanitized.replacements) == 2


def test_replacements_never_expose_raw_values() -> None:
    _, sanitized, _ = run("password = Sup3rS3cret! and key AKIAZ7Q2WJ5K3LMNOPQR")

    dumped = sanitized.model_dump_json()
    assert "Sup3rS3cret!" not in dumped
    assert "AKIAZ7Q2WJ5K3LMNOPQR" not in dumped


def test_source_code_finding_does_not_replace_whole_prompt() -> None:
    prompt = "import os\ndef load():\n    return os.environ['HOME']\n"
    detection, sanitized, _ = run(prompt)

    assert any(entity.category == "SOURCE_CODE" for entity in detection.detected_entities)
    assert sanitized.text == prompt


def test_restore_puts_back_pii_but_never_credentials() -> None:
    prompt = "Draft a reply to nimal@company.lk, my password = Sup3rS3cret!"
    _, sanitized, vault = run(prompt)

    reply = "Dear [EMAIL_ADDRESS_1], please do not share [PASSWORD_1]."
    restored = SANITIZER.restore(reply, sanitized, vault)

    assert restored == "Dear nimal@company.lk, please do not share [PASSWORD_1]."


def test_clean_prompt_scores_zero_and_is_allowed() -> None:
    detection, _, _ = run("Explain the difference between hashing and encryption.")
    assessment = ASSESSOR.assess(detection)

    assert assessment.score == 0
    assert assessment.level == RiskLevel.LOW
    assert assessment.recommended_action == RecommendedAction.ALLOW


def test_contact_detail_is_low_or_medium_and_sanitized() -> None:
    detection, _, _ = run("Please email the report to nimal@company.lk")
    assessment = ASSESSOR.assess(detection)

    assert assessment.level in {RiskLevel.LOW, RiskLevel.MEDIUM}
    assert assessment.recommended_action == RecommendedAction.SANITIZE


def test_private_key_is_critical_and_blocked() -> None:
    detection, _, _ = run("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA7v\n-----END RSA PRIVATE KEY-----")
    assessment = ASSESSOR.assess(detection)

    assert assessment.level == RiskLevel.CRITICAL
    assert assessment.recommended_action == RecommendedAction.BLOCK


def test_combining_categories_raises_the_score() -> None:
    card_only = ASSESSOR.assess(run("card 4539 1488 0343 6467")[0])
    card_and_identity = ASSESSOR.assess(run("card 4539 1488 0343 6467 for customer NIC 199512345678")[0])

    assert card_and_identity.score > card_only.score
    assert any(factor.entity_type == "CATEGORY_COMBINATION" for factor in card_and_identity.factors)


def test_score_is_capped_and_factors_explain_it() -> None:
    prompt = (
        "AWS AKIAZ7Q2WJ5K3LMNOPQR, password = hunter22, "
        "postgres://admin:hunter2@10.0.0.5:5432/prod, card 4539 1488 0343 6467"
    )
    assessment = ASSESSOR.assess(run(prompt)[0])

    assert assessment.score == 100
    assert assessment.level == RiskLevel.CRITICAL
    assert assessment.factors[0].points >= assessment.factors[-1].points
    assert "risk (100/100)" in assessment.summary
