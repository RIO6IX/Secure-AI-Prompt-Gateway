from __future__ import annotations

from detection_engine.models.response import DetectionResponse


class MetricsService:
    def __init__(self) -> None:
        self.prometheus_available = False
        self._registry = None
        try:
            from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

            self._registry = CollectorRegistry()
            self._prom = {
                "requests": Counter("detection_requests_total", "Detection requests", registry=self._registry),
                "errors": Counter("detection_errors_total", "Detection errors", ["code"], registry=self._registry),
                "processing": Histogram("detection_processing_seconds", "Detection processing seconds", registry=self._registry),
                "entities": Counter("detected_entities_total", "Detected entities", registry=self._registry),
                "by_category": Counter("detected_entities_by_category_total", "Detected entities by category", ["category"], registry=self._registry),
                "by_risk": Counter("detected_entities_by_risk_total", "Detected entities by risk", ["risk"], registry=self._registry),
                "detector_seconds": Histogram("detector_execution_seconds", "Detector execution seconds", ["detector"], registry=self._registry),
                "ner_available": Gauge("ner_model_available", "NER model available", registry=self._registry),
                "engine_ready": Gauge("engine_ready", "Engine ready", registry=self._registry),
            }
            self.prometheus_available = True
        except Exception:
            self._prom = {}
            self._fallback_requests = 0
            self._fallback_errors: dict[str, int] = {}

    def record_detection(self, response: DetectionResponse) -> None:
        if self.prometheus_available:
            self._prom["requests"].inc()
            self._prom["processing"].observe(response.processing_time_ms / 1000)
            self._prom["entities"].inc(response.entity_count)
            for category, count in response.category_summary.items():
                if count:
                    self._prom["by_category"].labels(category=category.value).inc(count)
            for entity in response.detected_entities:
                self._prom["by_risk"].labels(risk=entity.risk_level.value).inc()
        else:
            self._fallback_requests += 1

    def record_error(self, code: str) -> None:
        if self.prometheus_available:
            self._prom["errors"].labels(code=code).inc()
        else:
            self._fallback_errors[code] = self._fallback_errors.get(code, 0) + 1

    def observe_detector(self, detector: str, seconds: float) -> None:
        if self.prometheus_available:
            self._prom["detector_seconds"].labels(detector=detector).observe(seconds)

    def set_readiness(self, ready: bool, ner_available: bool) -> None:
        if self.prometheus_available:
            self._prom["engine_ready"].set(1 if ready else 0)
            self._prom["ner_available"].set(1 if ner_available else 0)

    def render(self) -> tuple[str, str]:
        if self.prometheus_available:
            from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

            return generate_latest(self._registry).decode("utf-8"), CONTENT_TYPE_LATEST
        lines = [f"detection_requests_total {self._fallback_requests}"]
        for code, count in sorted(self._fallback_errors.items()):
            lines.append(f'detection_errors_total{{code="{code}"}} {count}')
        return "\n".join(lines) + "\n", "text/plain; version=0.0.4"


metrics = MetricsService()
