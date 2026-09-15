from __future__ import annotations

PLACEHOLDERS = {
    "AKIAIOSFODNN7EXAMPLE",
    "example@example.com",
    "test@example.com",
    "user@example.com",
    "4111111111111111",
    "4111 1111 1111 1111",
    "localhost",
    "127.0.0.1",
    "::1",
    "example.com",
}

NEGATIVE_CONTEXT = {
    "example",
    "sample",
    "fake",
    "dummy",
    "mock",
    "placeholder",
    "test",
    "test data",
    "documentation",
    "tutorial",
    "checksum",
    "uuid",
    "hash",
}


def is_placeholder(value: str) -> bool:
    normalized = value.strip()
    compact = normalized.replace("-", "").replace(" ", "")
    return normalized in PLACEHOLDERS or compact in PLACEHOLDERS
