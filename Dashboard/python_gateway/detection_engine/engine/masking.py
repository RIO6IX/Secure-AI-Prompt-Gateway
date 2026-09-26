"""Masked previews of detected values.

The preview is what people see in the chat analysis panel, the audit log,
CSV exports and API responses, so it must identify *which* value was found
without disclosing it. The rules per data class:

- Secrets never reveal their own characters. At most the vendor's public
  prefix (``ghp_``, ``sk-proj-``, ``AKIA``) and the last four characters
  are shown, as GitHub and AWS consoles do. Passwords show nothing, not
  even their length.
- Card numbers show only the last four digits (PCI DSS allows at most the
  first six and last four). CVVs are never shown in any form.
- Connection strings and credential URLs keep scheme, host and path so an
  investigator can see which system was exposed; user and password go.
- Personal data keeps just enough to tell entries apart: email first
  letter and domain, name initials, last two phone digits, network part
  of an IP address. Addresses and dates of birth are hidden entirely.
"""

from __future__ import annotations

import re

FULL = "********"

# Public, fixed prefixes that identify the credential type without
# revealing anything secret. Longest first so "sk-ant-api03-" wins over "sk-".
VENDOR_PREFIXES = (
    "github_pat_", "sk-ant-admin01-", "sk-ant-api03-", "sk-svcacct-", "sk-admin-", "sk-proj-",
    "sk_live_", "sk_test_", "rk_live_", "whsec_", "glpat-", "xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-",
    "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "hf_", "npm_", "AKIA", "ASIA", "AIza", "SG.", "sk-",
)
TYPES_WITH_PREFIX = {
    "AWS_ACCESS_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GITHUB_TOKEN", "GITLAB_TOKEN",
    "GOOGLE_API_KEY", "STRIPE_SECRET_KEY", "STRIPE_WEBHOOK_SECRET", "SLACK_TOKEN",
    "HUGGINGFACE_TOKEN", "SENDGRID_API_KEY", "NPM_TOKEN",
}
FULLY_HIDDEN = {"PASSWORD", "CVV", "DATE_OF_BIRTH", "STREET_ADDRESS", "BASIC_AUTH_CREDENTIALS"}
URL_RE = re.compile(r"^(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*://)(?:[^@/\s]*@)?(?P<rest>.*)$")


def _last4(value: str) -> str:
    # Revealing the tail of a short secret gives away too large a share of it.
    return f"...{value[-4:]}" if len(value) >= 20 else ""


def _secret(value: str, entity_type: str) -> str:
    if entity_type in TYPES_WITH_PREFIX:
        prefix = next((p for p in VENDOR_PREFIXES if value.startswith(p)), "")
        if prefix:
            return f"{prefix}{FULL}{_last4(value)}"
    if entity_type == "JWT_TOKEN":
        return f"eyJ{FULL}"
    return f"{FULL}{_last4(value)}"


def _url(value: str) -> str:
    match = URL_RE.match(value)
    if not match:
        return FULL
    return f"{match['scheme']}****:****@{match['rest']}"


def _digits_tail(value: str, keep: int) -> str:
    digits = [char for char in value if char.isdigit()]
    if len(digits) <= keep + 3:
        return FULL
    return "*" * (len(digits) - keep) + "".join(digits[-keep:])


def _ip(value: str) -> str:
    if "." in value:
        parts = value.split(".")
        return ".".join(parts[:2] + ["*", "*"]) if len(parts) == 4 else FULL
    groups = value.split(":")
    return f"{groups[0]}:****:****" if groups and groups[0] else FULL


def _name(value: str) -> str:
    initials = [f"{word[0].upper()}." for word in value.split() if word[:1].isalpha()]
    return " ".join(initials) or FULL


def mask_value(entity_type: str, value: str) -> str:
    kind = entity_type.upper()
    value = value.strip()
    if not value or kind in FULLY_HIDDEN:
        return FULL
    if "PRIVATE_KEY" in kind:
        header = value.splitlines()[0] if value.startswith("-----BEGIN") else "-----BEGIN PRIVATE KEY-----"
        return f"{header} [{max(0, len(value.splitlines()) - 2)} lines redacted]"
    if kind in {"DATABASE_CONNECTION_STRING", "URL_WITH_CREDENTIALS", "SLACK_WEBHOOK"}:
        if kind == "SLACK_WEBHOOK":
            return f"https://hooks.slack.com/services/{FULL}"
        return _url(value)
    if kind == "EMAIL_ADDRESS" and "@" in value:
        local, domain = value.rsplit("@", 1)
        return f"{local[:1]}***@{domain}"
    if kind == "CREDIT_CARD_NUMBER":
        digits = "".join(char for char in value if char.isdigit())
        return f"**** **** **** {digits[-4:]}" if len(digits) >= 12 else FULL
    if kind == "IBAN":
        compact = value.replace(" ", "")
        return f"{compact[:4]} **** **** {compact[-4:]}" if len(compact) >= 12 else FULL
    if kind == "BANK_ACCOUNT_NUMBER":
        return _digits_tail(value, 4)
    if kind in {"PHONE_NUMBER", "SRI_LANKAN_NIC"}:
        return _digits_tail(value, 2) + (value[-1] if value[-1:].isalpha() else "")
    if kind == "PASSPORT_NUMBER":
        return f"{value[0]}{'*' * (len(value) - 3)}{value[-2:]}" if len(value) > 4 else FULL
    if kind in {"IP_ADDRESS", "IPV6_ADDRESS"}:
        return _ip(value)
    if kind == "PERSON_NAME":
        return _name(value)
    if kind in {"LOCATION", "ORGANIZATION", "SWIFT_BIC"}:
        return value  # public, low-risk context; kept for readability
    if kind in {"SOURCE_CODE", "PRIVATE_SOURCE_CODE"}:
        return f"[source code, {len(value.splitlines()) or 1} line(s)]"
    return _secret(value, kind)
