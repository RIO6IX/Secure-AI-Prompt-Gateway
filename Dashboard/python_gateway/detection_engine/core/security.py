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

    normalized_chars: list[str] = []
    mapping: list[int] = []
    for original_index, char in enumerate(prompt):
        # Invisible "format" characters (zero-width space/joiner, BOM, soft
        # hyphen, bidi overrides) are a known way to split a secret so that
        # "AKIA​ABC..." no longer matches. Drop them before matching;
        # the index map keeps spans pointing at the original prompt.
        if char == "\x00" or unicodedata.category(char) == "Cf":
            continue
        normalized = unicodedata.normalize("NFKC", char)
        for normalized_char in normalized:
            normalized_chars.append(normalized_char)
            mapping.append(original_index)
    return "".join(normalized_chars), mapping


def correlation_hash(value: str) -> str:
    return hashlib.sha256(f"{settings.correlation_salt}:{value}".encode("utf-8")).hexdigest()
