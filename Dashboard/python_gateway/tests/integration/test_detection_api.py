from fastapi.testclient import TestClient

import app as gateway_app
from app import app


client = TestClient(app)


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
    assert "****" in body["sanitizedPrompt"]
    assert "sk-proj-ABC1234567890secret" not in body["sanitizedPrompt"]
    assert body["componentExtensionPoints"]["component_02"].startswith("Prompt Sanitization")

    events = client.get(f"/audit/events?actor={admin_email}&status=Sanitized", headers=headers)
    assert events.status_code == 200
    event_rows = events.json()
    assert len(event_rows) == 1
    assert event_rows[0]["status"] == "Sanitized"
    assert "sk-proj-ABC1234567890secret" not in event_rows[0]["maskedOutput"]

    summary = client.get(f"/audit?actor={admin_email}&status=Sanitized", headers=headers)
    assert summary.status_code == 200
    assert summary.json()["totals"]["total"] == 1

    export = client.get(f"/reports/export?actor={admin_email}&status=Sanitized", headers=headers)
    assert export.status_code == 200
    assert "secure-ai-filtered-audit-report" not in export.text
    assert "sk-proj-ABC1234567890secret" not in export.text


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
