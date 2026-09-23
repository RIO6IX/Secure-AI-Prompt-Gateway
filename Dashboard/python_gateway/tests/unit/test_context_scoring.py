from detection_engine.engine.detection_engine import SensitiveDataDetectionEngine
from detection_engine.models.request import DetectRequest
from detection_engine.rules.keyword_match import keywords_in


def test_keyword_matching_is_whole_word() -> None:
    assert keywords_in("the company office", ["pan"]) == []
    assert keywords_in("run the latest build", ["test"]) == []
    assert keywords_in("my api_key is", ["api key"]) == ["api key"]
    assert keywords_in("card PAN on file", ["pan"]) == ["pan"]


def test_negative_context_never_hides_a_luhn_valid_card() -> None:
    result = SensitiveDataDetectionEngine().detect(
        DetectRequest(prompt="this is only a test example, card 4111 1111 1111 1111")
    )
    cards = [entity for entity in result.detected_entities if entity.entity_type == "CREDIT_CARD_NUMBER"]
    assert cards
    assert cards[0].confidence >= 0.5
