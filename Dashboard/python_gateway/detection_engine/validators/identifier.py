from __future__ import annotations

import re

OLD_NIC_RE = re.compile(r"^\d{9}[VX]$", re.IGNORECASE)
NEW_NIC_RE = re.compile(r"^\d{12}$")


def is_sri_lankan_nic_format(value: str) -> bool:
    normalized = value.strip().upper()
    return bool(OLD_NIC_RE.fullmatch(normalized) or NEW_NIC_RE.fullmatch(normalized))
