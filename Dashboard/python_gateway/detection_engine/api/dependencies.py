from __future__ import annotations

from functools import lru_cache

from detection_engine.engine.detection_engine import SensitiveDataDetectionEngine


@lru_cache(maxsize=1)
def get_detection_engine() -> SensitiveDataDetectionEngine:
    return SensitiveDataDetectionEngine()
