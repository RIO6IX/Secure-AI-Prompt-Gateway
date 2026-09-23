from __future__ import annotations

import base64
import binascii
import re

# Values that are clearly templates or examples, not real secrets.
PLACEHOLDER_WORDS = re.compile(
    r"(?i)^(?:changeme|change_me|your[_-].*|<.*>|\$\{.*\}|\$[A-Z_]+|%.*%|\{\{.*\}\}|x{4,}|\*{4,}|"
    r"none|null|nil|true|false|undefined|redacted|example|placeholder|dummy|secret|password|token)$"
)


def is_real_secret_value(value: str) -> bool:
    """Reject template values such as ${API_KEY}, <your-token>, xxxx, changeme."""
    if PLACEHOLDER_WORDS.match(value):
        return False
    return len(set(value)) > 3


def is_basic_auth(value: str) -> bool:
    """HTTP Basic credentials are base64("user:password")."""
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return False
    user, sep, password = decoded.partition(":")
    return bool(sep and user and password)
