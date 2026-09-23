from __future__ import annotations

import re

from detection_engine.detectors.base import BaseDetector, DetectionContext
from detection_engine.models.entities import DetectionCandidate, DetectionMethod, ValidationStatus
from detection_engine.rules.regex_rules import REGEX_RULES
from detection_engine.validators.date_of_birth import is_plausible_birth_date
from detection_engine.validators.email import is_email_valid
from detection_engine.validators.iban import is_iban_valid
from detection_engine.validators.identifier import is_sri_lankan_nic_format
from detection_engine.validators.ip_address import is_ip_valid
from detection_engine.validators.luhn import is_luhn_valid
from detection_engine.validators.secret_format import is_secret_format_valid
from detection_engine.validators.secret_value import is_basic_auth, is_real_secret_value


# Entity types whose validator is decisive: a failed check means the match is
# not that entity at all, so it is dropped instead of down-weighted.
STRICTLY_VALIDATED = {"IP_ADDRESS", "IPV6_ADDRESS", "CREDIT_CARD_NUMBER", "IBAN", "SRI_LANKAN_NIC", "DATE_OF_BIRTH", "GENERIC_API_KEY", "BASIC_AUTH_CREDENTIALS"}


# "version 1.2.3.4" / "v10.0.0.1" are software versions, not hosts.
VERSION_PREFIX_RE = re.compile(r"(?i)\b(?:version|ver\.?|release|build|v)\s*$")


class RegexDetector(BaseDetector):
    name = "regex_detector"

    def detect(self, text: str, context: DetectionContext) -> list[DetectionCandidate]:
        findings: list[DetectionCandidate] = []
        for rule in REGEX_RULES:
            if not rule.enabled:
                continue
            for match in rule.pattern.finditer(text):
                value = match.group(1) if match.lastindex else match.group(0)
                start, end = match.span(1) if match.lastindex else match.span(0)
                if rule.entity_type == "IP_ADDRESS" and VERSION_PREFIX_RE.search(text[max(0, start - 12):start]):
                    continue
                validation = self._validate(rule.validator_name, rule.entity_type, value)
                if validation in {ValidationStatus.FORMAT_INVALID, ValidationStatus.CHECKSUM_INVALID}:
                    if rule.entity_type in STRICTLY_VALIDATED:
                        continue
                findings.append(DetectionCandidate(
                    entity_type=rule.entity_type,
                    category=rule.category,
                    start=start,
                    end=end,
                    value=value,
                    confidence=rule.base_confidence,
                    risk_level=rule.default_risk,
                    validation_status=validation,
                    detection_methods=[DetectionMethod.REGEX],
                    rule_name=rule.name,
                ))
        return findings

    @staticmethod
    def _validate(validator: str | None, entity_type: str, value: str) -> ValidationStatus:
        if validator == "luhn":
            return ValidationStatus.CHECKSUM_VALID if is_luhn_valid(value) else ValidationStatus.CHECKSUM_INVALID
        if validator == "date_of_birth":
            return ValidationStatus.FORMAT_VALID if is_plausible_birth_date(value) else ValidationStatus.FORMAT_INVALID
        if validator == "secret_value":
            return ValidationStatus.NOT_VALIDATED if is_real_secret_value(value) else ValidationStatus.FORMAT_INVALID
        if validator == "basic_auth":
            return ValidationStatus.FORMAT_VALID if is_basic_auth(value) else ValidationStatus.FORMAT_INVALID
        if validator == "iban":
            return ValidationStatus.CHECKSUM_VALID if is_iban_valid(value) else ValidationStatus.CHECKSUM_INVALID
        if validator == "email":
            return ValidationStatus.FORMAT_VALID if is_email_valid(value) else ValidationStatus.FORMAT_INVALID
        if validator == "ip":
            return ValidationStatus.FORMAT_VALID if is_ip_valid(value) else ValidationStatus.FORMAT_INVALID
        if validator == "nic":
            return ValidationStatus.FORMAT_VALID if is_sri_lankan_nic_format(value) else ValidationStatus.FORMAT_INVALID
        if validator == "secret_format":
            return ValidationStatus.FORMAT_VALID if is_secret_format_valid(entity_type, value) else ValidationStatus.FORMAT_INVALID
        return ValidationStatus.NOT_VALIDATED
