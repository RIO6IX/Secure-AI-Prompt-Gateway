from __future__ import annotations

from datetime import datetime, timezone

from detection_engine import ENGINE_VERSION
from detection_engine.engine.detection_engine import SensitiveDataDetectionEngine


def health_payload(engine: SensitiveDataDetectionEngine) -> dict[str, object]:
    return {
        "status": "healthy",
        "component": "sensitive-data-detection-engine",
        "engine_version": ENGINE_VERSION,
        "ready": engine.ready,
        "ner_model_available": engine.ner_available,
        "presidio_available": engine.presidio_available,
        "time": datetime.now(timezone.utc).isoformat(),
    }
