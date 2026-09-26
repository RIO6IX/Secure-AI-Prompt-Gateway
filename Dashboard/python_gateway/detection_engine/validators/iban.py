from __future__ import annotations

import re

IBAN_RE = re.compile(r"^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$")


def is_iban_valid(value: str) -> bool:
    """ISO 13616 mod-97 check: move the first four characters to the end,
    convert letters to numbers (A=10 ... Z=35) and the remainder must be 1."""
    compact = value.replace(" ", "").upper()
    if not IBAN_RE.fullmatch(compact):
        return False
    rearranged = compact[4:] + compact[:4]
    numeric = "".join(str(int(char, 36)) for char in rearranged)
    return int(numeric) % 97 == 1
