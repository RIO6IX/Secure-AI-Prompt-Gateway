from __future__ import annotations

from detection_engine.core.security import normalize_prompt


def preprocess(prompt: str) -> tuple[str, list[int]]:
    return normalize_prompt(prompt)
