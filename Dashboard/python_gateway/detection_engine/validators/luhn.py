from __future__ import annotations

import re


def digits_only(value: str) -> str:
    return re.sub(r"[\s-]", "", value)


def is_luhn_valid(value: str) -> bool:
    digits = digits_only(value)
    if not digits.isdigit() or not 13 <= len(digits) <= 19:
        return False
    if len(set(digits)) == 1:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, char in enumerate(digits):
        digit = int(char)
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0
