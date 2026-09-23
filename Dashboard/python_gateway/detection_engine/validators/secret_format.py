from __future__ import annotations

import re


SECRET_FORMATS: dict[str, re.Pattern[str]] = {
    "AWS_ACCESS_KEY": re.compile(r"^AKIA[0-9A-Z]{16}$"),
    "OPENAI_API_KEY": re.compile(r"^sk-(proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,200}$"),
    "GITHUB_TOKEN": re.compile(r"^gh[pousr]_[A-Za-z0-9_]{20,255}$"),
    "GITLAB_TOKEN": re.compile(r"^glpat-[A-Za-z0-9_-]{20,255}$"),
    "GOOGLE_API_KEY": re.compile(r"^AIza[0-9A-Za-z_-]{35}$"),
    "STRIPE_SECRET_KEY": re.compile(r"^sk_(live|test)_[0-9A-Za-z]{10,255}$"),
    "SLACK_TOKEN": re.compile(r"^xox[baprs]-[A-Za-z0-9-]{10,255}$"),
    "JWT_TOKEN": re.compile(r"^[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$"),
}


def is_secret_format_valid(entity_type: str, value: str) -> bool:
    pattern = SECRET_FORMATS.get(entity_type)
    if pattern is None:
        return True
    return bool(pattern.fullmatch(value.strip()))
