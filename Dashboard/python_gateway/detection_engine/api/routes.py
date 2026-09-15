from __future__ import annotations

from uuid import uuid4

from fastapi import APIRouter, Depends, Response
from fastapi.responses import JSONResponse

from detection_engine import ENGINE_VERSION
from detection_engine.api.dependencies import get_detection_engine
from detection_engine.core.exceptions import DetectionError
from detection_engine.engine.detection_engine import SensitiveDataDetectionEngine
from detection_engine.models.request import BatchDetectRequest, DetectRequest
from detection_engine.models.response import BatchDetectionResponse, DetectionResponse
from detection_engine.services.health_service import health_payload
from detection_engine.services.metrics_service import metrics

router = APIRouter(prefix="/api/v1", tags=["Sensitive Data Detection Engine"])


@router.post("/detect", response_model=DetectionResponse)
def detect(
    payload: DetectRequest,
    engine: SensitiveDataDetectionEngine = Depends(get_detection_engine),
) -> DetectionResponse:
    try:
        return engine.detect(payload)
    except DetectionError as exc:
        metrics.record_error(exc.code)
        request_id = payload.request_id or str(uuid4())
        return JSONResponse(
            status_code=400,
            content={"error": {"code": exc.code, "message": exc.message, "request_id": request_id}},
        )


@router.post("/detect/batch", response_model=BatchDetectionResponse)
def detect_batch(
    payload: BatchDetectRequest,
    engine: SensitiveDataDetectionEngine = Depends(get_detection_engine),
) -> BatchDetectionResponse:
    try:
        return engine.detect_batch(payload)
    except DetectionError as exc:
        metrics.record_error(exc.code)
        return JSONResponse(
            status_code=400,
            content={"error": {"code": exc.code, "message": exc.message, "request_id": str(uuid4())}},
        )


@router.get("/health")
def detection_health(engine: SensitiveDataDetectionEngine = Depends(get_detection_engine)) -> dict[str, object]:
    metrics.set_readiness(engine.ready, engine.ner_available)
    return health_payload(engine)


@router.get("/ready")
def detection_ready(engine: SensitiveDataDetectionEngine = Depends(get_detection_engine)) -> dict[str, object]:
    metrics.set_readiness(engine.ready, engine.ner_available)
    return {
        "ready": engine.ready,
        "engine_version": ENGINE_VERSION,
        "required_modules": {
            "regex": True,
            "entropy": True,
            "financial": True,
            "source_code": True,
            "ner_optional_available": engine.ner_available,
        },
    }


def root_ready(engine: SensitiveDataDetectionEngine = Depends(get_detection_engine)) -> dict[str, object]:
    return detection_ready(engine)


def root_metrics() -> Response:
    body, media_type = metrics.render()
    return Response(body, media_type=media_type)
