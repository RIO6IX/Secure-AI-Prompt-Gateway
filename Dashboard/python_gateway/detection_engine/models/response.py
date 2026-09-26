from __future__ import annotations

from pydantic import BaseModel

from .entities import Category, DetectionMethod, RiskLevel, ValidationStatus


class DetectedEntity(BaseModel):
    entity_id: str
    entity_type: str
    category: Category
    start: int
    end: int
    masked_value: str
    confidence: float
    risk_level: RiskLevel
    validation_status: ValidationStatus
    detection_methods: list[DetectionMethod]
    rule_name: str
    context: str


class DetectionResponse(BaseModel):
    request_id: str
    contains_sensitive_data: bool
    overall_risk: RiskLevel
    risk_score: float
    entity_count: int
    processing_time_ms: float
    detected_entities: list[DetectedEntity]
    category_summary: dict[Category, int]
    engine_version: str
    warnings: list[str] = []


class BatchDetectionResponse(BaseModel):
    request_id: str
    results: list[DetectionResponse]
    engine_version: str


class ErrorBody(BaseModel):
    code: str
    message: str
    request_id: str


class ErrorResponse(BaseModel):
    error: ErrorBody
