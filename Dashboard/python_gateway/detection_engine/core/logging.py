from __future__ import annotations

import json
import logging
from typing import Any

from .config import settings

SENSITIVE_KEYS = {"prompt", "value", "raw", "secret", "password", "token", "card_number"}


class PrivacyFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        for key in SENSITIVE_KEYS:
            if hasattr(record, key):
                setattr(record, key, "[FILTERED]")
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key in (
            "request_id", "endpoint", "prompt_length", "entity_count", "overall_risk", "processing_time_ms",
            # security events (OWASP A09)
            "event", "actor", "client_ip", "path", "method", "status_code", "role", "target",
        ):
            if hasattr(record, key):
                payload[key] = getattr(record, key)
        return json.dumps(payload, separators=(",", ":"))


def configure_logging() -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    handler.addFilter(PrivacyFilter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(settings.log_level.upper())
