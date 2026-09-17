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
    assert "****" in body["sanitizedPrompt"]
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
