from detection_engine.engine.deduplicator import deduplicate
from detection_engine.engine.detection_engine import SensitiveDataDetectionEngine
from detection_engine.models.entities import Category, DetectionCandidate, DetectionMethod, RiskLevel, ValidationStatus
from detection_engine.models.request import DetectRequest


def candidate(entity_type: str, category: Category, start: int, end: int, **extra) -> DetectionCandidate:
    return DetectionCandidate(
        entity_type=entity_type,
        category=category,
        start=start,
        end=end,
        value="x" * (end - start),
        confidence=extra.pop("confidence", 0.8),
        risk_level=RiskLevel.HIGH,
        detection_methods=[DetectionMethod.REGEX],
        rule_name=entity_type.lower(),
        **extra,
    )


def test_source_code_finding_does_not_swallow_embedded_secrets() -> None:
    prompt = (
        "import os\n"
        "def connect():\n"
        "    password = 'Sup3rS3cret!'\n"
        "    return db.connect('postgres://admin:hunter2@10.0.0.5:5432/prod')\n"
    )
    result = SensitiveDataDetectionEngine().detect(DetectRequest(prompt=prompt))
    types = {entity.entity_type for entity in result.detected_entities}

    assert "SOURCE_CODE" in types
    assert "PASSWORD" in types
    assert "DATABASE_CONNECTION_STRING" in types
    # The IP address sits inside the connection string and is folded into it.
    assert "IP_ADDRESS" not in types


def test_more_specific_entity_wins_over_validated_generic_overlap() -> None:
    connection = candidate("DATABASE_CONNECTION_STRING", Category.CREDENTIAL, 10, 60)
    ip = candidate("IP_ADDRESS", Category.PII, 30, 38, validation_status=ValidationStatus.FORMAT_VALID)

    merged = deduplicate([ip, connection])

    assert [item.entity_type for item in merged] == ["DATABASE_CONNECTION_STRING"]


def test_bridging_candidate_collapses_all_overlaps() -> None:
    left = candidate("PHONE_NUMBER", Category.PII, 0, 10)
    right = candidate("PHONE_NUMBER", Category.PII, 12, 20)
    bridge = candidate("CREDIT_CARD_NUMBER", Category.FINANCIAL, 5, 15, validation_status=ValidationStatus.CHECKSUM_VALID)

    merged = deduplicate([left, right, bridge])

    assert len(merged) == 1
    assert merged[0].entity_type == "CREDIT_CARD_NUMBER"


def test_only_one_document_level_finding_is_kept() -> None:
    weak = candidate("SOURCE_CODE", Category.SOURCE_CODE, 0, 100, confidence=0.5)
    strong = candidate("PRIVATE_SOURCE_CODE", Category.SOURCE_CODE, 0, 100, confidence=0.7)
    email = candidate("EMAIL_ADDRESS", Category.PII, 20, 40)

    merged = deduplicate([weak, email, strong])

    assert {item.entity_type for item in merged} == {"EMAIL_ADDRESS", "PRIVATE_SOURCE_CODE"}
