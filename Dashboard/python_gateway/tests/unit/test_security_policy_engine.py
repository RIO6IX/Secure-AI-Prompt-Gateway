from detection_engine.engine.detection_engine import SensitiveDataDetectionEngine
from detection_engine.models.request import DetectRequest
from security_policy import PolicyAction, PolicyEngine, PolicyInput, UserContext


def evaluate_prompt(
    prompt: str, *, role: str = "admin", forward_requested: bool = True, mask_secrets: bool = False,
):
    detector = SensitiveDataDetectionEngine()
    policy = PolicyEngine(mask_secrets=mask_secrets)
    detection = detector.detect(DetectRequest(prompt=prompt))
    return policy.evaluate(
        PolicyInput(
            user=UserContext(email=f"{role}@example.com", name=role.title(), role=role),
            detection=detection,
            service="Ollama Qwen2.5",
            department="Security",
            forward_requested=forward_requested,
        )
    )


def test_allows_clean_authenticated_prompt() -> None:
    decision = evaluate_prompt("Explain how password hashing works in general.")

    assert decision.action == PolicyAction.ALLOW
    assert decision.allowed_to_forward is True
    assert decision.requires_sanitization is False
    assert decision.rule_id == "POL-ALLOW-001"


def test_blocks_read_only_role_from_prompt_processing() -> None:
    decision = evaluate_prompt("Summarise this safe text.", role="auditor")

    assert decision.action == PolicyAction.BLOCK
    assert decision.allowed_to_forward is False
    assert decision.audit_status == "Blocked"
    assert decision.rule_id == "POL-RBAC-001"


def test_blocks_credential_material() -> None:
    decision = evaluate_prompt("My API key is sk-proj-ABC1234567890secret, please fix this.")

    assert decision.action == PolicyAction.BLOCK
    assert decision.allowed_to_forward is False
    assert decision.requires_sanitization is True
    assert decision.rule_id == "POL-CRED-001"


def test_masks_credential_material_when_configured() -> None:
    decision = evaluate_prompt("My API key is sk-proj-ABC1234567890secret, please fix this.", mask_secrets=True)

    assert decision.action == PolicyAction.SANITIZE
    assert decision.allowed_to_forward is True
    assert decision.requires_sanitization is True
    assert decision.rule_id == "POL-CRED-001"


def test_mask_mode_still_blocks_read_only_roles() -> None:
    decision = evaluate_prompt("Summarise this safe text.", role="auditor", mask_secrets=True)

    assert decision.action == PolicyAction.BLOCK
    assert decision.allowed_to_forward is False


def test_sanitizes_personal_data_when_forwarding_is_requested() -> None:
    decision = evaluate_prompt("Please email the report to customer@example.com.")

    assert decision.action == PolicyAction.SANITIZE
    assert decision.allowed_to_forward is True
    assert decision.requires_sanitization is True
    assert decision.rule_id == "POL-PII-001"


def test_respects_user_forwarding_choice_after_sanitization() -> None:
    decision = evaluate_prompt("Please email the report to customer@example.com.", forward_requested=False)

    assert decision.action == PolicyAction.SANITIZE
    assert decision.allowed_to_forward is False
    assert decision.requires_sanitization is True
