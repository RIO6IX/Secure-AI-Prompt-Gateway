from __future__ import annotations


def mask_value(entity_type: str, value: str) -> str:
    if not value:
        return "****"
    compact_type = entity_type.upper()
    if "EMAIL" in compact_type and "@" in value:
        local, domain = value.split("@", 1)
        return f"{local[:1]}***@{domain}"
    if "CREDIT_CARD" in compact_type:
        digits = "".join(ch for ch in value if ch.isdigit())
        return f"**** **** **** {digits[-4:]}" if len(digits) >= 4 else "****"
    if compact_type in {"PHONE_NUMBER", "SRI_LANKAN_NIC", "CVV"}:
        return "*" * max(4, len(value) - 1) + value[-1:]
    if "PRIVATE_KEY" in compact_type:
        return "-----BEGIN [REDACTED] PRIVATE KEY-----"
    if compact_type == "JWT_TOKEN":
        return f"{value[:3]}**************{value[-3:]}" if len(value) > 8 else "****"
    if len(value) <= 8:
        return "****"
    return f"{value[:4]}{'*' * min(16, max(4, len(value) - 8))}{value[-4:]}"
