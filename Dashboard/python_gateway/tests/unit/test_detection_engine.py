from detection_engine.engine.detection_engine import SensitiveDataDetectionEngine
from detection_engine.models.request import DetectRequest


def test_benign_prompt_returns_no_entities() -> None:
    engine = SensitiveDataDetectionEngine()
    result = engine.detect(DetectRequest(prompt="Explain the difference between hashing and encryption."))
    assert result.contains_sensitive_data is False
    assert result.entity_count == 0
    assert result.overall_risk == "LOW"


def test_credentials_email_and_card_are_detected_without_raw_secret_leakage() -> None:
    engine = SensitiveDataDetectionEngine()
    result = engine.detect(DetectRequest(prompt="AWS key AKIAIOSFODNN7EXAMPLE email user@example.com test card 4111 1111 1111 1111"))
    types = {entity.entity_type for entity in result.detected_entities}
    assert "AWS_ACCESS_KEY" in types
    assert "EMAIL_ADDRESS" in types
    assert "CREDIT_CARD_NUMBER" in types
    assert all("AKIAIOSFODNN7EXAMPLE" not in entity.masked_value for entity in result.detected_entities)


def test_cvv_requires_context_and_sri_lankan_nic_uses_context() -> None:
    engine = SensitiveDataDetectionEngine()
    no_cvv = engine.detect(DetectRequest(prompt="The code is 123"))
    assert "CVV" not in {entity.entity_type for entity in no_cvv.detected_entities}
    cvv = engine.detect(DetectRequest(prompt="The card CVV is 123"))
    assert "CVV" in {entity.entity_type for entity in cvv.detected_entities}
    nic = engine.detect(DetectRequest(prompt="Customer NIC number is 123456789V"))
    assert "SRI_LANKAN_NIC" in {entity.entity_type for entity in nic.detected_entities}


def test_python_phrase_alone_is_not_source_code_but_code_block_is() -> None:
    engine = SensitiveDataDetectionEngine()
    phrase = engine.detect(DetectRequest(prompt="Please debug this Python code."))
    assert "SOURCE_CODE" not in {entity.entity_type for entity in phrase.detected_entities}
    code = engine.detect(DetectRequest(prompt="def hello(name):\n    print('hello', name)\nimport os\n"))
    assert "SOURCE_CODE" in {entity.entity_type for entity in code.detected_entities}
