from __future__ import annotations

import os
from dataclasses import dataclass


def _bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    max_prompt_length: int = int(os.getenv("MAX_PROMPT_LENGTH", "50000"))
    max_batch_size: int = int(os.getenv("MAX_BATCH_SIZE", "100"))
    max_batch_total_chars: int = int(os.getenv("MAX_BATCH_TOTAL_CHARS", "250000"))
    default_min_confidence: float = float(os.getenv("DEFAULT_MIN_CONFIDENCE", "0.35"))
    entropy_threshold: float = float(os.getenv("ENTROPY_THRESHOLD", "3.7"))
    entropy_min_length: int = int(os.getenv("ENTROPY_MIN_LENGTH", "16"))
    entropy_max_length: int = int(os.getenv("ENTROPY_MAX_LENGTH", "256"))
    enable_ner: bool = _bool("ENABLE_NER", True)
    enable_metrics: bool = _bool("ENABLE_METRICS", True)
    spacy_model: str = os.getenv("SPACY_MODEL", "en_core_web_sm")
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    # NER is the only super-linear stage; beyond this many characters it is
    # skipped (regex, checksum and entropy rules still scan everything).
    ner_max_chars: int = int(os.getenv("NER_MAX_CHARS", "20000"))
    correlation_salt: str = os.getenv("CORRELATION_SALT", "local-dev-salt-change-me")


settings = Settings()
