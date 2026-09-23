import pytest
from fastapi.testclient import TestClient

import app as gateway_app
from app import app


client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_prompt_rate_limit():
    gateway_app.prompt_rate_limiter.reset()
    yield
    gateway_app.prompt_rate_limiter.reset()


def test_detect_endpoint() -> None:
    response = client.post("/api/v1/detect", json={"prompt": "contact user@example.com"})
    assert response.status_code == 200
    body = response.json()
    assert body["contains_sensitive_data"] is True
    assert body["detected_entities"][0]["entity_type"] == "EMAIL_ADDRESS"


def test_batch_health_ready_and_metrics() -> None:
    batch = client.post("/api/v1/detect/batch", json={"prompts": [{"prompt": "hello"}, {"prompt": "card CVV 123"}]})
    assert batch.status_code == 200
    assert len(batch.json()["results"]) == 2
    assert client.get("/health").status_code == 200
    assert client.get("/ready").json()["ready"] is True
    metrics = client.get("/metrics")
    assert metrics.status_code == 200
    assert "detection_requests_total" in metrics.text


def test_empty_prompt_error_shape() -> None:
    response = client.post("/api/v1/detect", json={"prompt": "   "})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "EMPTY_PROMPT"


def test_security_headers_and_password_strength(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(gateway_app, "DB_PATH", tmp_path / "audit.sqlite3")
    gateway_app.init_db()

    response = client.post(
        "/auth/register",
        json={"name": "Weak User", "email": "weak@example.com", "password": "password"},
    )

    assert response.status_code == 400
    assert "password must be at least" in response.json()["detail"]
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["cache-control"] == "no-store"


def test_login_throttles_repeated_failed_attempts(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(gateway_app, "DB_PATH", tmp_path / "audit.sqlite3")
    gateway_app.login_failures.clear()
    gateway_app.init_db()

    register = client.post(
        "/auth/register",
        json={"name": "Rate Limit User", "email": "rate-limit@example.com", "password": "SecurePass123!"},
    )
    assert register.status_code == 201

    for _ in range(gateway_app.LOGIN_MAX_ATTEMPTS):
        failed = client.post("/auth/login", json={"email": "rate-limit@example.com", "password": "WrongPass123!"})
        assert failed.status_code == 401

    throttled = client.post("/auth/login", json={"email": "rate-limit@example.com", "password": "WrongPass123!"})
    assert throttled.status_code == 429
    assert throttled.json()["detail"].startswith("Too many failed login attempts")


def test_legacy_password_hashes_still_login_after_hardening(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(gateway_app, "DB_PATH", tmp_path / "audit.sqlite3")
    gateway_app.init_db()

    legacy_hash = gateway_app.hashlib.pbkdf2_hmac(
        "sha256",
        "SecurePass123!".encode("utf-8"),
        "legacy-salt".encode("utf-8"),
        120_000,
    ).hex()
    with gateway_app.connect() as connection:
        connection.execute(
            """
            INSERT INTO users (id, name, email, password_hash, role, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "USR-LEGACY",
                "Legacy User",
                "legacy.chanuka@example.com",
                f"legacy-salt${legacy_hash}",
                "admin",
                "2026-09-22T00:00:00+00:00",
            ),
        )

    login = client.post(
        "/auth/login",
        json={"email": "legacy.chanuka@example.com", "password": "SecurePass123!"},
    )

    assert login.status_code == 200
    assert login.json()["user"]["role"] == "admin"


def test_cors_allows_admin_delete_preflight() -> None:
    response = client.options(
        "/admin/users/USR-123",
        headers={
            "origin": "http://localhost:3000",
            "access-control-request-method": "DELETE",
        },
    )

    assert response.status_code == 200
    assert "DELETE" in response.headers["access-control-allow-methods"]


def test_gateway_masks_sensitive_prompt_and_filterable_audit_logs(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(gateway_app, "DB_PATH", tmp_path / "audit.sqlite3")
    gateway_app.init_db()

    admin_email = "chanuka.admin@example.com"
    login_payload = {"name": "Chanuka Admin", "email": admin_email, "password": "SecurePass123!"}
    register = client.post("/auth/register", json=login_payload)
    assert register.status_code == 201
    token = register.json()["token"]
    headers = {"authorization": f"Bearer {token}"}

    prompt = "Fix login. API key is sk-proj-ABC1234567890secret and email user@example.com"
    gateway = client.post(
        "/gateway/chat",
        headers=headers,
        json={"prompt": prompt, "service": "Ollama Qwen2.5", "forward_to_ollama": False},
    )
    assert gateway.status_code == 200
    body = gateway.json()
    assert body["containsSensitiveData"] is True
    assert body["policyDecision"] == "BLOCK"
    assert body["policyResult"]["rule_id"] == "POL-CRED-001"
    assert body["replacements"][0]["category"] == "CREDENTIAL"
    assert body["sanitizedPrompt"].startswith("Fix login. API key is [")
    assert "[EMAIL_ADDRESS_1]" in body["sanitizedPrompt"]
    assert "sk-proj-ABC1234567890secret" not in body["sanitizedPrompt"]
    assert "sk-proj-ABC1234567890secret" not in body["assistantMessage"]
    assert body["componentExtensionPoints"]["component_02"].startswith("Prompt Sanitization")
    assert body["componentExtensionPoints"]["component_03"].startswith("Security Policy")

    events = client.get(f"/audit/events?actor={admin_email}&status=Blocked", headers=headers)
    assert events.status_code == 200
    event_rows = events.json()
    assert len(event_rows) == 1
    assert event_rows[0]["status"] == "Blocked"
    assert event_rows[0]["policyRule"].startswith("POL-CRED-001")
    assert "sk-proj-ABC1234567890secret" not in event_rows[0]["maskedOutput"]

    summary = client.get(f"/audit?actor={admin_email}&status=Blocked", headers=headers)
    assert summary.status_code == 200
    assert summary.json()["totals"]["total"] == 1

    policies = client.get("/policies", headers=headers)
    assert policies.status_code == 200
    assert any(policy["id"] == "POL-CRED-001" and policy["action"] == "BLOCK" for policy in policies.json()["policies"])

    export = client.get(f"/reports/export?actor={admin_email}&status=Blocked", headers=headers)
    assert export.status_code == 200
    assert "secure-ai-filtered-audit-report" not in export.text
    assert "sk-proj-ABC1234567890secret" not in export.text


def test_gateway_blocks_short_password_before_forwarding(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(gateway_app, "DB_PATH", tmp_path / "audit.sqlite3")
    gateway_app.init_db()

    register = client.post(
        "/auth/register",
        json={"name": "Password Admin", "email": "password.admin@example.com", "password": "SecurePass123!"},
    )
    assert register.status_code == 201
    headers = {"authorization": f"Bearer {register.json()['token']}"}

    gateway = client.post(
        "/gateway/chat",
        headers=headers,
        json={"prompt": "password = 1234", "service": "Ollama Qwen2.5", "forward_to_ollama": True},
    )

    assert gateway.status_code == 200
    body = gateway.json()
    assert body["containsSensitiveData"] is True
    assert body["policyDecision"] == "BLOCK"
    assert body["policyResult"]["rule_id"] == "POL-CRED-001"
    assert body["sanitizedPrompt"] == "password = [PASSWORD_1]"
    assert "1234" not in body["sanitizedPrompt"]
    assert "1234" not in body["assistantMessage"]
    assert body["ollamaAvailable"] is False
    assert any(entity["entityType"] == "PASSWORD" for entity in body["detectedEntities"])


def test_audit_write_boundary_masks_raw_sensitive_output(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(gateway_app, "DB_PATH", tmp_path / "audit.sqlite3")
    gateway_app.init_db()

    register = client.post(
        "/auth/register",
        json={"name": "Audit Admin", "email": "audit.boundary@example.com", "password": "SecurePass123!"},
    )
    assert register.status_code == 201
    headers = {"authorization": f"Bearer {register.json()['token']}"}

    event = {
        "actor": "audit.boundary@example.com",
        "department": "Security",
        "service": "Ollama Qwen2.5",
        "action": "Prompt analyzed",
        "status": "Allowed",
        "risk": "Low",
        "riskScore": 0,
        "finding": "No sensitive data detected",
        "category": "Clean",
        "policyRule": "Client supplied audit event",
        "maskedOutput": "password = 1234",
        "source": "browser-extension",
    }

    create_event = client.post("/audit/events", headers=headers, json=event)
    assert create_event.status_code == 201
    created = create_event.json()
    assert created["maskedOutput"] == "password = ****"
    assert created["status"] == "Sanitized"
    assert created["risk"] == "Critical"
    assert created["finding"] == "Password"
    assert "1234" not in created["maskedOutput"]

    events = client.get("/audit/events?actor=audit.boundary@example.com", headers=headers)
    assert events.status_code == 200
    rows = events.json()
    assert rows[0]["maskedOutput"] == "password = ****"
    assert rows[0]["policyRule"] == "Audit write boundary sanitization enforced"

    export = client.get("/reports/export?actor=audit.boundary@example.com", headers=headers)
    assert export.status_code == 200
    assert "password = ****" in export.text
    assert "1234" not in export.text


def test_audit_export_trims_filters_and_escapes_spreadsheet_formulas(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(gateway_app, "DB_PATH", tmp_path / "audit.sqlite3")
    gateway_app.init_db()

    login_payload = {"name": "Chanuka Admin", "email": "chanuka.report@example.com", "password": "SecurePass123!"}
    register = client.post("/auth/register", json=login_payload)
    assert register.status_code == 201
    headers = {"authorization": f"Bearer {register.json()['token']}"}

    event = {
        "actor": "=2+2",
        "department": "Security",
        "service": "=cmd|' /C calc'!A0",
        "action": "Policy blocked prompt",
        "status": "Blocked",
        "risk": "High",
        "riskScore": 90,
        "finding": "Formula-like audit value",
        "category": "Credential",
        "policyRule": "@policy",
        "maskedOutput": "+masked",
        "source": "-browser-extension",
    }
    create_event = client.post("/audit/events", headers=headers, json=event)
    assert create_event.status_code == 201

    export = client.get(
        "/reports/export",
        headers=headers,
        params={"actor": " =2+2 ", "service": " =cmd ", "status": " Blocked "},
    )
    assert export.status_code == 200
    assert "\"'=2+2\"" in export.text
    assert "\"'=cmd|' /C calc'!A0\"" in export.text
    assert "\"'@policy\"" in export.text
    assert "\"'+masked\"" in export.text
    assert "\"'-browser-extension\"" in export.text


def test_gateway_returns_clear_error_for_blank_prompt(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(gateway_app, "DB_PATH", tmp_path / "audit.sqlite3")
    gateway_app.init_db()

    register = client.post(
        "/auth/register",
        json={"name": "Chanuka Admin", "email": "chanuka.blank@example.com", "password": "SecurePass123!"},
    )
    assert register.status_code == 201
    headers = {"authorization": f"Bearer {register.json()['token']}"}

    response = client.post(
        "/gateway/chat",
        headers=headers,
        json={"prompt": "   ", "service": "Ollama Qwen2.5", "forward_to_ollama": False},
    )

    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "EMPTY_PROMPT"


def register_admin(tmp_path, monkeypatch, email: str) -> dict[str, str]:
    monkeypatch.setattr(gateway_app, "DB_PATH", tmp_path / "audit.sqlite3")
    gateway_app.init_db()
    register = client.post(
        "/auth/register",
        json={"name": "Gateway Admin", "email": email, "password": "SecurePass123!"},
    )
    assert register.status_code == 201
    return {"authorization": f"Bearer {register.json()['token']}"}


def test_inspect_uses_detection_engine_and_token_identity(tmp_path, monkeypatch) -> None:
    headers = register_admin(tmp_path, monkeypatch, "inspect.admin@example.com")

    response = client.post(
        "/inspect",
        headers=headers,
        json={
            "actor": "someone.else@example.com",
            "service": "ChatGPT Enterprise",
            "prompt": "Connect with postgres://admin:hunter2@10.0.0.5:5432/prod please",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["actor"] == "inspect.admin@example.com"
    assert body["status"] == "Blocked"
    assert body["finding"] == "Database Connection String"
    assert "hunter2" not in body["maskedOutput"]
    assert body.get("originalPrompt") is None


def test_gateway_writes_one_audit_record_per_prompt(tmp_path, monkeypatch) -> None:
    headers = register_admin(tmp_path, monkeypatch, "one.record@example.com")

    for prompt in ("What is a hash function?", "email me at nimal@company.lk"):
        response = client.post("/gateway/chat", headers=headers, json={"prompt": prompt, "forward_to_ollama": False})
        assert response.status_code == 200

    summary = client.get("/audit", headers=headers).json()
    assert summary["totals"]["total"] == 2
    assert summary["totals"]["sensitive"] == 1


def test_remote_audit_outage_does_not_fail_the_request(tmp_path, monkeypatch) -> None:
    headers = register_admin(tmp_path, monkeypatch, "remote.outage@example.com")
    monkeypatch.setattr(gateway_app, "REMOTE_AUDIT_API_URL", "http://127.0.0.1:9/unreachable")

    response = client.post(
        "/inspect",
        headers=headers,
        json={"service": "ChatGPT Enterprise", "prompt": "hello there"},
    )

    assert response.status_code == 200
    assert response.json()["remoteId"] is None


def test_auditor_can_review_logs_but_cannot_process_prompts(tmp_path, monkeypatch) -> None:
    admin_headers = register_admin(tmp_path, monkeypatch, "policy.admin@example.com")

    auditor_create = client.post(
        "/admin/users",
        headers=admin_headers,
        json={
            "name": "Policy Auditor",
            "email": "policy.auditor@example.com",
            "password": "AuditPass123!",
            "role": "auditor",
        },
    )
    assert auditor_create.status_code == 201
    auditor_headers = {"authorization": f"Bearer {auditor_create.json()['token']}"}

    assert client.get("/audit/events", headers=auditor_headers).status_code == 200

    blocked_prompt = client.post(
        "/gateway/chat",
        headers=auditor_headers,
        json={"prompt": "Explain this general question", "forward_to_ollama": False},
    )
    assert blocked_prompt.status_code == 403
    assert blocked_prompt.json()["detail"] == "You do not have permission for this action"


def test_sanitize_endpoint_returns_placeholders_and_writes_one_audit_record(tmp_path, monkeypatch) -> None:
    headers = register_admin(tmp_path, monkeypatch, "extension.user@example.com")

    response = client.post(
        "/api/v1/sanitize",
        headers=headers,
        json={"prompt": "Reply to nimal@company.lk about the invoice", "service": "ChatGPT"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "SANITIZE"
    assert body["sanitizedPrompt"] == "Reply to [EMAIL_ADDRESS_1] about the invoice"
    assert body["replacements"][0]["placeholder"] == "[EMAIL_ADDRESS_1]"
    assert "nimal@company.lk" not in response.text

    events = client.get("/audit/events?actor=extension.user@example.com", headers=headers).json()
    assert len(events) == 1
    assert events[0]["source"] == "browser-extension"
    assert events[0]["id"] == body["auditId"]
    assert "nimal@company.lk" not in events[0]["maskedOutput"]


def test_sanitize_endpoint_returns_no_text_for_blocked_prompt(tmp_path, monkeypatch) -> None:
    headers = register_admin(tmp_path, monkeypatch, "extension.block@example.com")

    response = client.post(
        "/api/v1/sanitize",
        headers=headers,
        json={"prompt": "deploy with password = Sup3rS3cret!", "service": "ChatGPT"},
    )

    body = response.json()
    assert body["decision"] == "BLOCK"
    assert body["sanitizedPrompt"] == ""
    assert "Sup3rS3cret!" not in response.text


def test_critical_combined_risk_blocks_even_when_each_rule_only_sanitizes(tmp_path, monkeypatch) -> None:
    headers = register_admin(tmp_path, monkeypatch, "risk.escalation@example.com")
    prompt = (
        "Refund Priya Fernando, NIC 199512345678, card 4539 1488 0343 6467 cvv 123, "
        "IBAN GB82WEST12345698765432, phone +94 77 123 4567, email priya@acme.lk"
    )

    body = client.post("/api/v1/sanitize", headers=headers, json={"prompt": prompt}).json()

    assert body["policyResult"]["action"] == "SANITIZE"
    assert body["riskLevel"] == "CRITICAL"
    assert body["decision"] == "BLOCK"
    events = client.get("/audit/events?actor=risk.escalation@example.com", headers=headers).json()
    assert events[0]["status"] == "Blocked"
    assert events[0]["policyRule"].startswith("RISK-CRITICAL")


def test_gateway_restores_pii_in_model_reply_only(tmp_path, monkeypatch) -> None:
    headers = register_admin(tmp_path, monkeypatch, "restore.user@example.com")
    sent: list[str] = []

    async def fake_ollama(prompt: str) -> tuple[str, bool]:
        sent.append(prompt)
        return "Draft: Hello [EMAIL_ADDRESS_1], your request was received.", True

    monkeypatch.setattr(gateway_app, "call_ollama", fake_ollama)
    body = client.post(
        "/gateway/chat",
        headers=headers,
        json={"prompt": "Write a short reply to nimal@company.lk", "forward_to_ollama": True},
    ).json()

    assert sent == ["Write a short reply to [EMAIL_ADDRESS_1]"]
    assert body["assistantMessage"] == "Draft: Hello nimal@company.lk, your request was received."
    assert body["policyDecision"] == "SANITIZE"
    assert body["riskAssessment"]["factors"][0]["entity_type"] == "EMAIL_ADDRESS"


def test_ordinary_question_with_a_place_name_is_allowed(tmp_path, monkeypatch) -> None:
    headers = register_admin(tmp_path, monkeypatch, "place.name@example.com")

    body = client.post("/api/v1/sanitize", headers=headers, json={"prompt": "What is the capital of Sri Lanka?"}).json()

    assert body["decision"] == "ALLOW"
    assert body["sanitizedPrompt"] == "What is the capital of Sri Lanka?"


def test_repeated_blocked_attempts_escalate_the_next_sensitive_prompt(tmp_path, monkeypatch) -> None:
    headers = register_admin(tmp_path, monkeypatch, "repeat.probe@example.com")
    for attempt in ("password = Sup3rS3cret!", "password = Sup3rS3cret!2"):
        assert client.post("/api/v1/sanitize", headers=headers, json={"prompt": attempt}).json()["decision"] == "BLOCK"

    body = client.post("/api/v1/sanitize", headers=headers, json={"prompt": "mail nimal@company.lk"}).json()

    factors = {factor["entity_type"]: factor["points"] for factor in body["riskAssessment"]["factors"]}
    assert factors["REPEATED_ATTEMPTS"] == 20
    clean = client.post("/api/v1/sanitize", headers=headers, json={"prompt": "What is a hash?"}).json()
    assert clean["decision"] == "ALLOW"


def test_prompt_endpoints_are_rate_limited_per_user(tmp_path, monkeypatch) -> None:
    headers = register_admin(tmp_path, monkeypatch, "rate.limited@example.com")
    monkeypatch.setattr(gateway_app, "prompt_rate_limiter", gateway_app.SlidingWindowLimiter(3, 60))

    statuses = [
        client.post("/api/v1/sanitize", headers=headers, json={"prompt": "hello"}).status_code
        for _ in range(4)
    ]

    assert statuses == [200, 200, 200, 429]
    limited = client.post("/gateway/chat", headers=headers, json={"prompt": "hi", "forward_to_ollama": False})
    assert limited.status_code == 429
    assert int(limited.headers["retry-after"]) >= 1
