from __future__ import annotations

from pydantic import BaseModel, Field


class DetectionOptions(BaseModel):
    enable_ner: bool = True
    enable_entropy: bool = True
    enable_source_code_detection: bool = True
    minimum_confidence: float = Field(default=0.35, ge=0.0, le=1.0)


class DetectRequest(BaseModel):
    prompt: str
    request_id: str | None = None
    language: str = "en"
    options: DetectionOptions = Field(default_factory=DetectionOptions)


class BatchDetectRequest(BaseModel):
    prompts: list[DetectRequest]
