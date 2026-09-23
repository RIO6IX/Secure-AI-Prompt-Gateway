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


# "password is: x", "pwd = x", "passcode: x". Words that usually follow "is" in
# ordinary sentences ("my password is too short") are not values; they only
# count when they stand alone, so "correct-horse-battery" is still captured.
PASSWORD_FILLER_WORDS = (
    "a|an|the|too|not|wrong|incorrect|invalid|expired|same|correct|required|missing|"
    "empty|reset|changed|weak|strong|different|case|still|also|now|being|very|mine|yours"
)
PASSWORD_PATTERN = (
    # (?<![A-Za-z0-9]) instead of \b so env names like DB_PASSWORD match; the
    # optional quote after the key covers JSON/YAML ("password": "x").
    r"(?i)(?<![A-Za-z0-9])(?:password|passwd|pwd|passcode)(?![A-Za-z0-9])[\"']?\s*(?:is\s*[:=]?|[:=])\s*[\"']?"
    rf"(?!(?:{PASSWORD_FILLER_WORDS})(?:[\s.,!?]|$))"
    r"([^\s,;\"':=][^\s,;\"']{0,127})[\"']?"
)


REGEX_RULES: tuple[RegexRule, ...] = (
    RegexRule("aws_access_key_id", "AWS_ACCESS_KEY", Category.CREDENTIAL, re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 0.90, RiskLevel.CRITICAL, ("aws", "access key", "secret"), "secret_format"),
    RegexRule("aws_secret_access_key", "AWS_SECRET_ACCESS_KEY", Category.CREDENTIAL, re.compile(r"(?i)\b(?:aws_?secret_?access_?key|aws_?secret_?key|secret_?access_?key)[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"), 0.92, RiskLevel.CRITICAL, ("aws", "secret"), None),
    RegexRule("anthropic_api_key", "ANTHROPIC_API_KEY", Category.CREDENTIAL, re.compile(r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{20,200}\b"), 0.95, RiskLevel.CRITICAL, ("anthropic", "claude", "api key"), "secret_format"),
    RegexRule("openai_api_key", "OPENAI_API_KEY", Category.CREDENTIAL, re.compile(r"\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,200}\b"), 0.90, RiskLevel.CRITICAL, ("openai", "api key"), "secret_format"),
    RegexRule("huggingface_token", "HUGGINGFACE_TOKEN", Category.CREDENTIAL, re.compile(r"\bhf_[A-Za-z0-9]{30,40}\b"), 0.90, RiskLevel.CRITICAL, ("hugging face", "huggingface", "token"), "secret_format"),
    RegexRule("azure_storage_account_key", "AZURE_STORAGE_KEY", Category.CREDENTIAL, re.compile(r"(?i)\bAccountKey=([A-Za-z0-9+/]{86}==)"), 0.95, RiskLevel.CRITICAL, ("azure", "storage", "connection"), None),
    RegexRule("gcp_service_account_key", "GCP_SERVICE_ACCOUNT_KEY", Category.CREDENTIAL, re.compile(r"\"private_key_id\"\s*:\s*\"([a-f0-9]{40})\""), 0.92, RiskLevel.CRITICAL, ("service_account", "gcp", "google cloud"), None),
    RegexRule("sendgrid_api_key", "SENDGRID_API_KEY", Category.CREDENTIAL, re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"), 0.95, RiskLevel.CRITICAL, ("sendgrid", "email"), "secret_format"),
    RegexRule("npm_access_token", "NPM_TOKEN", Category.CREDENTIAL, re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), 0.93, RiskLevel.CRITICAL, ("npm", "registry", "token"), "secret_format"),
    RegexRule("slack_webhook_url", "SLACK_WEBHOOK", Category.CREDENTIAL, re.compile(r"https://hooks\.slack\.com/(?:services|workflows)/[A-Za-z0-9/_-]{20,120}"), 0.93, RiskLevel.CRITICAL, ("slack", "webhook"), None),
    RegexRule("telegram_bot_token", "TELEGRAM_BOT_TOKEN", Category.CREDENTIAL, re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b"), 0.90, RiskLevel.CRITICAL, ("telegram", "bot"), None),
    RegexRule("github_token", "GITHUB_TOKEN", Category.CREDENTIAL, re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,255}\b"), 0.92, RiskLevel.CRITICAL, ("github", "token"), "secret_format"),
    RegexRule("gitlab_token", "GITLAB_TOKEN", Category.CREDENTIAL, re.compile(r"\bglpat-[A-Za-z0-9_-]{20,255}\b"), 0.92, RiskLevel.CRITICAL, ("gitlab", "token"), "secret_format"),
    RegexRule("google_api_key", "GOOGLE_API_KEY", Category.CREDENTIAL, re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), 0.92, RiskLevel.CRITICAL, ("google", "api key"), "secret_format"),
    RegexRule("stripe_secret_key", "STRIPE_SECRET_KEY", Category.CREDENTIAL, re.compile(r"\bsk_(?:live|test)_[0-9A-Za-z]{10,255}\b"), 0.92, RiskLevel.CRITICAL, ("stripe", "secret"), "secret_format"),
    RegexRule("slack_token", "SLACK_TOKEN", Category.CREDENTIAL, re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,255}\b"), 0.90, RiskLevel.CRITICAL, ("slack", "token"), "secret_format"),
    RegexRule("jwt_token", "JWT_TOKEN", Category.CREDENTIAL, re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), 0.88, RiskLevel.HIGH, ("jwt", "bearer", "authorization"), "secret_format"),
    RegexRule("bearer_token", "BEARER_TOKEN", Category.CREDENTIAL, re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._~+/=-]{16,256})\b"), 0.86, RiskLevel.CRITICAL, ("authorization", "bearer"), None),
    RegexRule("password_assignment", "PASSWORD", Category.CREDENTIAL, re.compile(PASSWORD_PATTERN), 0.90, RiskLevel.CRITICAL, ("password", "pwd"), None),
    RegexRule("generic_api_key", "GENERIC_API_KEY", Category.CREDENTIAL, re.compile(r"(?i)\b(?:api[_ -]?key|secret|token)\s*[:=]\s*[\"']?([A-Za-z0-9._~+/=-]{16,128})[\"']?"), 0.78, RiskLevel.HIGH, ("api key", "secret", "token"), None),
    RegexRule("database_connection_string", "DATABASE_CONNECTION_STRING", Category.CREDENTIAL, re.compile(r"(?i)\b(?:postgresql|postgres|mysql|mongodb|redis|mssql)://[^\s'\"<>]{8,256}"), 0.88, RiskLevel.CRITICAL, ("database", "connection", "password"), None),
    # Private keys match the whole block, not just the BEGIN line: the key
    # material is in the body. A block pasted without its END line (a common
    # truncated paste) runs to the end of the prompt.
    RegexRule("ssh_private_key_block", "SSH_PRIVATE_KEY", Category.CREDENTIAL, re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?(?:-----END OPENSSH PRIVATE KEY-----|\Z)"), 0.99, RiskLevel.CRITICAL, ("private key",), None),
    RegexRule("pem_private_key_block", "PEM_PRIVATE_KEY", Category.CREDENTIAL, re.compile(r"-----BEGIN (?:RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----|\Z)"), 0.99, RiskLevel.CRITICAL, ("private key",), None),
    RegexRule("pgp_private_key_block", "PGP_PRIVATE_KEY", Category.CREDENTIAL, re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?(?:-----END PGP PRIVATE KEY BLOCK-----|\Z)"), 0.99, RiskLevel.CRITICAL, ("private key", "pgp"), None),
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
