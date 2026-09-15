from __future__ import annotations

import re

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}$")


def is_email_valid(value: str) -> bool:
    if not EMAIL_RE.match(value):
        return False
    local, domain = value.rsplit("@", 1)
    return bool(local) and ".." not in domain and not domain.startswith("-") and not domain.endswith("-")
