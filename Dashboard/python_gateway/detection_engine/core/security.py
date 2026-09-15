from __future__ import annotations

import hashlib
import unicodedata

from .config import settings
from .exceptions import EmptyPromptError, PromptTooLargeError


def normalize_prompt(prompt: str) -> tuple[str, list[int]]:
    if prompt is None or not prompt.strip():
        raise EmptyPromptError()
    if len(prompt) > settings.max_prompt_length:
        raise PromptTooLargeError()

    cleaned = prompt.replace("\x00", "")
    normalized_chars: list[str] = []
    mapping: list[int] = []
    for original_index, char in enumerate(cleaned):
        normalized = unicodedata.normalize("NFKC", char)
        for normalized_char in normalized:
            normalized_chars.append(normalized_char)
            mapping.append(original_index)
    return "".join(normalized_chars), mapping


def correlation_hash(value: str) -> str:
    return hashlib.sha256(f"{settings.correlation_salt}:{value}".encode("utf-8")).hexdigest()
