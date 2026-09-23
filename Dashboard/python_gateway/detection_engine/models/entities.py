from __future__ import annotations

from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field


class Category(StrEnum):
    CREDENTIAL = "CREDENTIAL"
    PII = "PII"
    FINANCIAL = "FINANCIAL"
    SOURCE_CODE = "SOURCE_CODE"


class RiskLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ValidationStatus(StrEnum):
    FORMAT_VALID = "FORMAT_VALID"
    FORMAT_INVALID = "FORMAT_INVALID"
    NOT_VALIDATED = "NOT_VALIDATED"
    CONTEXT_CONFIRMED = "CONTEXT_CONFIRMED"
    CHECKSUM_VALID = "CHECKSUM_VALID"
    CHECKSUM_INVALID = "CHECKSUM_INVALID"


class DetectionMethod(StrEnum):
    REGEX = "REGEX"
    ENTROPY = "ENTROPY"
    CHECKSUM = "CHECKSUM"
    NER = "NER"
    CONTEXT = "CONTEXT"
    SOURCE_CODE_HEURISTIC = "SOURCE_CODE_HEURISTIC"


class DetectionCandidate(BaseModel):
    entity_id: str = Field(default_factory=lambda: f"ent-{uuid4().hex}")
    entity_type: str
    category: Category
    start: int
    end: int
    value: str = Field(exclude=True)
    confidence: float
    risk_level: RiskLevel
    validation_status: ValidationStatus = ValidationStatus.NOT_VALIDATED
    detection_methods: list[DetectionMethod]
    rule_name: str
    context: str = ""
    language_guess: str | None = None
    metadata: dict[str, int | float | str | bool] = Field(default_factory=dict)
