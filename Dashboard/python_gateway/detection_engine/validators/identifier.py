from __future__ import annotations

import re
from datetime import date

OLD_NIC_RE = re.compile(r"^(\d{2})(\d{3})\d{4}[VX]$", re.IGNORECASE)
NEW_NIC_RE = re.compile(r"^(\d{4})(\d{3})\d{5}$")


def _valid_day_of_year(day: int) -> bool:
    # Sri Lankan NICs encode the birth day-of-year; women get +500.
    return 1 <= day <= 366 or 501 <= day <= 866


def is_sri_lankan_nic_format(value: str) -> bool:
    normalized = value.strip().upper()
    old = OLD_NIC_RE.fullmatch(normalized)
    if old:
        return _valid_day_of_year(int(old.group(2)))
    new = NEW_NIC_RE.fullmatch(normalized)
    if new:
        year = int(new.group(1))
        return 1900 <= year <= date.today().year and _valid_day_of_year(int(new.group(2)))
    return False
