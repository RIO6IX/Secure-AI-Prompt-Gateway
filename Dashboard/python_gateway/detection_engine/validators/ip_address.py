from __future__ import annotations

import ipaddress


def is_ip_valid(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True
