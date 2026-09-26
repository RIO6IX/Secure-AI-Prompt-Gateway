from __future__ import annotations

import logging
import time
from uuid import uuid4

from detection_engine import ENGINE_VERSION
from detection_engine.core.config import settings
from detection_engine.core.exceptions import BatchTooLargeError
from detection_engine.detectors.base import DetectionContext
from detection_engine.detectors.entropy_detector import EntropyDetector
from detection_engine.detectors.pii_detector import PiiDetector
from detection_engine.detectors.regex_detector import RegexDetector
from detection_engine.detectors.source_code_detector import SourceCodeDetector
from detection_engine.engine.aggregator import enhance_candidate
from detection_engine.engine.deduplicator import deduplicate
from detection_engine.engine.masking import mask_value
from detection_engine.engine.preprocessor import preprocess
from detection_engine.engine.risk_classifier import classify_entity, overall_risk
from detection_engine.models.entities import Category, DetectionCandidate
from detection_engine.models.request import BatchDetectRequest, DetectRequest
from detection_engine.models.response import BatchDetectionResponse, DetectedEntity, DetectionResponse
from detection_engine.services.metrics_service import metrics

LOGGER = logging.getLogger(__name__)


class SensitiveDataDetectionEngine:
    def __init__(self) -> None:
        self.regex_detector = RegexDetector()
        self.entropy_detector = EntropyDetector()
        self.source_code_detector = SourceCodeDetector()
        self.pii_detector = PiiDetector()
        self.ready = True

    @property
    def ner_available(self) -> bool:
        return self.pii_detector.model_available

    @property
    def presidio_available(self) -> bool:
        return self.pii_detector.presidio_available

    def detect(self, request: DetectRequest) -> DetectionResponse:
        started = time.perf_counter()
        request_id = request.request_id or str(uuid4())
        normalized, index_map = preprocess(request.prompt)
        context = DetectionContext(
            language=request.language,
            original_text=request.prompt,
            normalized_text=normalized,
            index_map=index_map,
        )

        candidates: list[DetectionCandidate] = []
        detector_runs = [
            ("regex", self.regex_detector.detect),
        ]
        if request.options.enable_entropy:
            detector_runs.append(("entropy", self.entropy_detector.detect))
        if request.options.enable_source_code_detection:
            detector_runs.append(("source_code", self.source_code_detector.detect))
        if request.options.enable_ner and settings.enable_ner:
            detector_runs.append(("ner", self.pii_detector.detect))

        for detector_name, detector in detector_runs:
            detector_started = time.perf_counter()
            try:
                candidates.extend(detector(normalized, context))
            finally:
                metrics.observe_detector(detector_name, time.perf_counter() - detector_started)

        enhanced = [classify_entity(enhance_candidate(candidate, normalized)) for candidate in candidates]
        filtered = [candidate for candidate in deduplicate(enhanced) if candidate.confidence >= request.options.minimum_confidence]
        overall, score = overall_risk(filtered)
        entities = [
            DetectedEntity(
                entity_id=candidate.entity_id,
                entity_type=candidate.entity_type,
                category=candidate.category,
                start=self._original_index(index_map, candidate.start),
                end=self._original_end_index(index_map, candidate.end),
                masked_value=mask_value(candidate.entity_type, candidate.value),
                confidence=round(candidate.confidence, 3),
                risk_level=candidate.risk_level,
                validation_status=candidate.validation_status,
                detection_methods=candidate.detection_methods,
                rule_name=candidate.rule_name,
                context=candidate.context,
            )
            for candidate in filtered
        ]
        summary = {category: 0 for category in Category}
        for candidate in filtered:
            summary[candidate.category] += 1
        elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
        response = DetectionResponse(
            request_id=request_id,
            contains_sensitive_data=bool(filtered),
            overall_risk=overall,
            risk_score=score,
            entity_count=len(filtered),
            processing_time_ms=elapsed_ms,
            detected_entities=entities,
            category_summary=summary,
            engine_version=ENGINE_VERSION,
            warnings=context.warnings,
        )
        metrics.record_detection(response)
        LOGGER.info(
            "detection completed",
            extra={
                "request_id": request_id,
                "endpoint": "/api/v1/detect",
                "prompt_length": len(request.prompt),
                "entity_count": len(filtered),
                "overall_risk": overall.value,
                "processing_time_ms": elapsed_ms,
            },
        )
        return response

    def detect_batch(self, request: BatchDetectRequest) -> BatchDetectionResponse:
        if len(request.prompts) > settings.max_batch_size:
            raise BatchTooLargeError("Batch contains too many prompts.")
        total_chars = sum(len(item.prompt) for item in request.prompts)
        if total_chars > settings.max_batch_total_chars:
            raise BatchTooLargeError("Batch exceeds the total character limit.")
        return BatchDetectionResponse(
            request_id=str(uuid4()),
            results=[self.detect(item) for item in request.prompts],
            engine_version=ENGINE_VERSION,
        )

    @staticmethod
    def _original_index(index_map: list[int], normalized_index: int) -> int:
        if not index_map:
            return normalized_index
        if normalized_index >= len(index_map):
            return index_map[-1] + 1
        return index_map[normalized_index]

    @staticmethod
    def _original_end_index(index_map: list[int], normalized_end: int) -> int:
        if not index_map:
            return normalized_end
        if normalized_end <= 0:
            return 0
        if normalized_end - 1 >= len(index_map):
            return index_map[-1] + 1
        return index_map[normalized_end - 1] + 1
