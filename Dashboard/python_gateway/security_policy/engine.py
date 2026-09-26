from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

from detection_engine.models.entities import Category, RiskLevel
from detection_engine.models.response import DetectionResponse


class PolicyAction(StrEnum):
    ALLOW = "ALLOW"
    SANITIZE = "SANITIZE"
    BLOCK = "BLOCK"


class UserContext(BaseModel):
    email: str
    name: str
    role: str


class PolicyInput(BaseModel):
    user: UserContext
    detection: DetectionResponse
    service: str
    department: str = "Unknown"
    forward_requested: bool = True


class PolicyRule(BaseModel):
    rule_id: str
    name: str
    action: PolicyAction
    enabled: bool = True
    description: str
    standards: list[str] = Field(default_factory=list)


class PolicyDecision(BaseModel):
    action: PolicyAction
    rule_id: str
    rule_name: str
    reason: str
    allowed_to_forward: bool
    requires_sanitization: bool
    audit_status: str
    recommendation: str
    standards: list[str]


class PolicyEngine:
    """Component 03: Security Policy & Access Control Engine."""

    def __init__(self) -> None:
        self.rules = [
            PolicyRule(
                rule_id="POL-RBAC-001",
                name="Only admin and user roles can process prompts",
                action=PolicyAction.BLOCK,
                description="Auditor accounts can inspect audit evidence but cannot submit prompts to AI providers.",
                standards=["ISO/IEC 27001 access control", "PCI DSS unique access and need-to-know"],
            ),
            PolicyRule(
                rule_id="POL-CRED-001",
                name="Block credential and secret exposure",
                action=PolicyAction.BLOCK,
                description="Critical credential material must not be forwarded to an AI model even after masking.",
                standards=["ISO/IEC 27001 risk treatment", "PCI DSS protect authentication data"],
            ),
            PolicyRule(
                rule_id="POL-PCI-001",
                name="Sanitize payment card data",
                action=PolicyAction.SANITIZE,
                description="Payment data can proceed only after masking and audit logging.",
                standards=["PCI DSS protect stored account data", "GDPR data protection by design"],
            ),
            PolicyRule(
                rule_id="POL-PII-001",
                name="Sanitize personal data",
                action=PolicyAction.SANITIZE,
                description="PII can proceed only after masking and audit logging.",
                standards=["GDPR data minimisation", "GDPR data protection by design"],
            ),
            PolicyRule(
                rule_id="POL-SRC-001",
                name="Sanitize proprietary source code",
                action=PolicyAction.SANITIZE,
                description="Source code and internal IP can proceed only after masking and audit logging.",
                standards=["ISO/IEC 27001 confidentiality controls"],
            ),
            PolicyRule(
                rule_id="POL-ALLOW-001",
                name="Allow low risk prompt",
                action=PolicyAction.ALLOW,
                description="Prompts without sensitive findings may be forwarded by an authenticated user.",
                standards=["Least privilege", "Auditability"],
            ),
        ]

    def active_rules(self) -> list[PolicyRule]:
        return [rule for rule in self.rules if rule.enabled]

    def evaluate(self, policy_input: PolicyInput) -> PolicyDecision:
        role = policy_input.user.role.strip().lower()
        if role not in {"admin", "user"}:
            return self._decision(
                "POL-RBAC-001",
                reason="This role is read-only for prompt processing.",
                allowed_to_forward=False,
                requires_sanitization=False,
                audit_status="Blocked",
                recommendation="Use an admin or user account to process prompts.",
            )

        detection = policy_input.detection
        if not detection.contains_sensitive_data:
            return self._decision(
                "POL-ALLOW-001",
                reason="No sensitive data was detected.",
                allowed_to_forward=policy_input.forward_requested,
                requires_sanitization=False,
                audit_status="Allowed",
                recommendation="Allow prompt forwarding and keep audit evidence.",
            )

        categories = {entity.category for entity in detection.detected_entities}
        entity_types = {entity.entity_type.upper() for entity in detection.detected_entities}
        critical_secret = (
            detection.overall_risk == RiskLevel.CRITICAL
            and Category.CREDENTIAL in categories
        )
        block_secret_types = {
            "AWS_ACCESS_KEY",
            "API_KEY",
            "OPENAI_API_KEY",
            "GOOGLE_API_KEY",
            "GITHUB_TOKEN",
            "GITLAB_TOKEN",
            "HIGH_ENTROPY_SECRET",
            "STRIPE_SECRET_KEY",
            "SLACK_TOKEN",
            "JWT",
            "PASSWORD",
            "DATABASE_CONNECTION_STRING",
            "PRIVATE_KEY",
        }
        if critical_secret or entity_types.intersection(block_secret_types):
            return self._decision(
                "POL-CRED-001",
                reason="Credential or secret material was detected.",
                allowed_to_forward=False,
                requires_sanitization=True,
                audit_status="Blocked",
                recommendation="Block forwarding, rotate exposed secrets if real, and keep an audit record.",
            )

        if Category.FINANCIAL in categories:
            return self._decision(
                "POL-PCI-001",
                reason="Payment or financial data was detected.",
                allowed_to_forward=policy_input.forward_requested,
                requires_sanitization=True,
                audit_status="Sanitized",
                recommendation="Mask payment data before forwarding and retain compliance audit evidence.",
            )

        if Category.PII in categories:
            return self._decision(
                "POL-PII-001",
                reason="Personal data was detected.",
                allowed_to_forward=policy_input.forward_requested,
                requires_sanitization=True,
                audit_status="Sanitized",
                recommendation="Mask personal data before forwarding and minimise retained data.",
            )

        if Category.SOURCE_CODE in categories:
            return self._decision(
                "POL-SRC-001",
                reason="Source code or internal intellectual property was detected.",
                allowed_to_forward=policy_input.forward_requested,
                requires_sanitization=True,
                audit_status="Sanitized",
                recommendation="Mask proprietary code before forwarding.",
            )

        return self._decision(
            "POL-PII-001",
            reason="Sensitive data was detected and requires masking.",
            allowed_to_forward=policy_input.forward_requested,
            requires_sanitization=True,
            audit_status="Sanitized",
            recommendation="Mask sensitive values before forwarding.",
        )

    def _decision(
        self,
        rule_id: str,
        *,
        reason: str,
        allowed_to_forward: bool,
        requires_sanitization: bool,
        audit_status: str,
        recommendation: str,
    ) -> PolicyDecision:
        rule = next(item for item in self.rules if item.rule_id == rule_id)
        return PolicyDecision(
            action=rule.action,
            rule_id=rule.rule_id,
            rule_name=rule.name,
            reason=reason,
            allowed_to_forward=allowed_to_forward,
            requires_sanitization=requires_sanitization,
            audit_status=audit_status,
            recommendation=recommendation,
            standards=rule.standards,
        )
