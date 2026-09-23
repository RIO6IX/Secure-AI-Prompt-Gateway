from __future__ import annotations

import re
from dataclasses import dataclass

from detection_engine.models.entities import Category, RiskLevel


@dataclass(frozen=True)
class RegexRule:
    name: str
    entity_type: str
    category: Category
    pattern: re.Pattern[str]
    base_confidence: float
    default_risk: RiskLevel
    context_keywords: tuple[str, ...] = ()
    validator_name: str | None = None
    enabled: bool = True


REGEX_RULES: tuple[RegexRule, ...] = (
    RegexRule("aws_access_key_id", "AWS_ACCESS_KEY", Category.CREDENTIAL, re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 0.90, RiskLevel.CRITICAL, ("aws", "access key", "secret"), "secret_format"),
    RegexRule("github_token", "GITHUB_TOKEN", Category.CREDENTIAL, re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,255}\b"), 0.92, RiskLevel.CRITICAL, ("github", "token"), "secret_format"),
    RegexRule("gitlab_token", "GITLAB_TOKEN", Category.CREDENTIAL, re.compile(r"\bglpat-[A-Za-z0-9_-]{20,255}\b"), 0.92, RiskLevel.CRITICAL, ("gitlab", "token"), "secret_format"),
    RegexRule("google_api_key", "GOOGLE_API_KEY", Category.CREDENTIAL, re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), 0.92, RiskLevel.CRITICAL, ("google", "api key"), "secret_format"),
    RegexRule("stripe_secret_key", "STRIPE_SECRET_KEY", Category.CREDENTIAL, re.compile(r"\bsk_(?:live|test)_[0-9A-Za-z]{10,255}\b"), 0.92, RiskLevel.CRITICAL, ("stripe", "secret"), "secret_format"),
    RegexRule("slack_token", "SLACK_TOKEN", Category.CREDENTIAL, re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,255}\b"), 0.90, RiskLevel.CRITICAL, ("slack", "token"), "secret_format"),
    RegexRule("jwt_token", "JWT_TOKEN", Category.CREDENTIAL, re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), 0.88, RiskLevel.HIGH, ("jwt", "bearer", "authorization"), "secret_format"),
    RegexRule("bearer_token", "BEARER_TOKEN", Category.CREDENTIAL, re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._~+/=-]{16,256})\b"), 0.86, RiskLevel.CRITICAL, ("authorization", "bearer"), None),
    RegexRule("password_assignment", "PASSWORD", Category.CREDENTIAL, re.compile(r"(?i)\b(?:password|passwd|pwd)\s*(?:is|:|=)\s*[\"']?([^\s,;\"']{1,128})[\"']?"), 0.90, RiskLevel.CRITICAL, ("password", "pwd"), None),
    RegexRule("generic_api_key", "GENERIC_API_KEY", Category.CREDENTIAL, re.compile(r"(?i)\b(?:api[_ -]?key|secret|token)\s*[:=]\s*[\"']?([A-Za-z0-9._~+/=-]{16,128})[\"']?"), 0.78, RiskLevel.HIGH, ("api key", "secret", "token"), None),
    RegexRule("database_connection_string", "DATABASE_CONNECTION_STRING", Category.CREDENTIAL, re.compile(r"(?i)\b(?:postgresql|postgres|mysql|mongodb|redis|mssql)://[^\s'\"<>]{8,256}"), 0.88, RiskLevel.CRITICAL, ("database", "connection", "password"), None),
    RegexRule("ssh_private_key_header", "SSH_PRIVATE_KEY", Category.CREDENTIAL, re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"), 0.99, RiskLevel.CRITICAL, ("private key",), None),
    RegexRule("pem_private_key_header", "PEM_PRIVATE_KEY", Category.CREDENTIAL, re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"), 0.99, RiskLevel.CRITICAL, ("private key",), None),
    RegexRule("email_address", "EMAIL_ADDRESS", Category.PII, re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}\b"), 0.68, RiskLevel.MEDIUM, ("email", "contact"), "email"),
    RegexRule("phone_number", "PHONE_NUMBER", Category.PII, re.compile(r"(?<![\w+.-])(?:\+\d{1,3}[-.\s]?|0)?\(?\d{2,4}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?![\w-])"), 0.56, RiskLevel.MEDIUM, ("phone", "mobile", "call"), None),
    RegexRule("ipv4_address", "IP_ADDRESS", Category.PII, re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), 0.58, RiskLevel.MEDIUM, ("ip", "host", "server"), "ip"),
    RegexRule("ipv6_address", "IPV6_ADDRESS", Category.PII, re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"), 0.58, RiskLevel.MEDIUM, ("ipv6", "host"), "ip"),
    RegexRule("url_with_credentials", "URL_WITH_CREDENTIALS", Category.PII, re.compile(r"(?i)\bhttps?://[A-Za-z0-9._%+-]{1,64}:[^@\s]{1,128}@[^\s/$.?#].[^\s]{1,200}"), 0.90, RiskLevel.CRITICAL, ("url", "credentials"), None),
    RegexRule("sri_lankan_old_nic", "SRI_LANKAN_NIC", Category.PII, re.compile(r"\b\d{9}[VXvx]\b"), 0.55, RiskLevel.MEDIUM, ("nic", "identity", "national identity card"), "nic"),
    RegexRule("sri_lankan_new_nic", "SRI_LANKAN_NIC", Category.PII, re.compile(r"\b\d{12}\b"), 0.42, RiskLevel.LOW, ("nic", "identity", "national identity card"), "nic"),
    RegexRule("credit_card_candidate", "CREDIT_CARD_NUMBER", Category.FINANCIAL, re.compile(r"\b\d(?:[ -]?\d){12,18}\b"), 0.52, RiskLevel.MEDIUM, ("credit card", "card", "payment"), "luhn"),
    RegexRule("cvv_context", "CVV", Category.FINANCIAL, re.compile(r"(?i)\b(?:cvv|cvc|security code|card verification value)\s*(?:is|:|=)?\s*(\d{3,4})\b"), 0.76, RiskLevel.HIGH, ("cvv", "cvc", "security code"), None),
    RegexRule("iban", "IBAN", Category.FINANCIAL, re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"), 0.64, RiskLevel.MEDIUM, ("iban", "bank"), "iban"),
    RegexRule("swift_bic", "SWIFT_BIC", Category.FINANCIAL, re.compile(r"(?i:\b(?:swift|bic)(?:\s+code)?\s*(?:is|:|=)?\s*)\b([A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b"), 0.62, RiskLevel.LOW, ("swift", "bic", "bank"), None),
)
