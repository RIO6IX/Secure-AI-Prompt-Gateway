from __future__ import annotations

import re
from collections.abc import Iterable
from functools import lru_cache


@lru_cache(maxsize=512)
def _keyword_pattern(keyword: str) -> re.Pattern[str]:
    # Whole-word match so "pan" does not fire on "company" and "test" does not
    # fire on "latest"; inner spaces also match underscores/hyphens (api_key).
    body = r"[\s_-]+".join(re.escape(part) for part in keyword.split())
    return re.compile(rf"(?<![a-z0-9]){body}(?![a-z0-9])")


def keywords_in(window: str, keywords: Iterable[str]) -> list[str]:
    lowered = window.lower()
    return [keyword for keyword in keywords if _keyword_pattern(keyword).search(lowered)]
