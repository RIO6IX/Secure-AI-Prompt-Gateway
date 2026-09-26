"""Regression tests for the OWASP controls listed in docs/owasp-controls.md."""

import asyncio
import json
import logging

import httpx
import pytest
from fastapi.testclient import TestClient

import app as gateway_app
from app import app
from detection_engine.core.logging import JsonFormatter


client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_state(tmp_path, monkeypatch):
    monkeypatch.setattr(gateway_app, "DB_PATH", tmp_path / "audit.sqlite3")
    gateway_app.init_db()
    gateway_app.prompt_rate_limiter.reset()
    gateway_app.login_failures.clear()
    gateway_app.CONVERSATIONS.reset()
    yield
    gateway_app.prompt_rate_limiter.reset()
    gateway_app.login_failures.clear()
    gateway_app.CONVERSATIONS.reset()


def register(email: str) -> dict[str, str]:
    response = client.post("/auth/register", json={"name": "Owasp Test", "email": email, "password": "SecurePass123!"})
    assert response.status_code == 201
    return {"authorization": f"Bearer {response.json()['token']}"}


def create_user(admin: dict[str, str], email: str, role: str) -> dict[str, str]:
    response = client.post(
        "/admin/users", headers=admin, json={"name": "Member", "email": email, "password": "MemberPass123!", "role": role},
    )
    assert response.status_code == 201
    return {"authorization": f"Bearer {response.json()['token']}"}


async def fake_ollama(prompt: str, history=None) -> tuple[str, bool]:
    return "ok", True


# --- A01 Broken Access Control -------------------------------------------------

def test_plain_user_audit_summary_only_shows_their_own_prompts(monkeypatch) -> None:
    monkeypatch.setattr(gateway_app, "call_ollama", fake_ollama)
    admin = register("owner.admin@example.com")
    user = create_user(admin, "plain.user@example.com", "user")
    client.post("/gateway/chat", headers=admin, json={"prompt": "Explain how photosynthesis works."})
    client.post("/gateway/chat", headers=user, json={"prompt": "Explain how rainbows form."})

    user_view = client.get("/audit", headers=user).json()
    assert {event["actor"] for event in user_view["recentEvents"]} == {"plain.user@example.com"}
    assert user_view["totals"]["total"] == 1
    # Asking for someone else's events does not widen the scope.
    assert client.get("/audit?actor=owner.admin", headers=user).json()["totals"]["total"] == 0

    admin_view = client.get("/audit", headers=admin).json()
    assert admin_view["totals"]["total"] == 2


# --- A05 Security Misconfiguration ---------------------------------------------

def test_health_does_not_disclose_the_siem_url(monkeypatch) -> None:
    monkeypatch.setattr(gateway_app, "REMOTE_AUDIT_API_URL", "https://siem.internal.example/ingest")
    body = client.get("/health").json()
    assert "siem.internal.example" not in str(body)
    assert body["remoteAuditConfigured"] is True


def test_api_responses_carry_a_restrictive_content_security_policy() -> None:
    response = client.get("/health")
    assert response.headers["content-security-policy"] == "default-src 'none'; frame-ancestors 'none'"
    assert response.headers["x-frame-options"] == "DENY"


# --- A03 Injection / LLM10 Unbounded Consumption -------------------------------

def test_free_text_metadata_fields_are_length_limited() -> None:
    admin = register("limits.admin@example.com")
    response = client.post("/gateway/chat", headers=admin, json={"prompt": "hi", "department": "x" * 500})
    assert response.status_code == 422


def test_oversized_password_is_rejected_before_hashing() -> None:
    response = client.post("/auth/login", json={"email": "a@example.com", "password": "x" * 10_000})
    assert response.status_code == 422


def test_model_output_length_is_capped(monkeypatch) -> None:
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = request.read().decode()
        return httpx.Response(200, json={"message": {"content": "ok"}})

    real_client = httpx.AsyncClient

    def client_factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(gateway_app.httpx, "AsyncClient", client_factory)
    assert asyncio.run(gateway_app.call_ollama("hello")) == ("ok", True)
    assert f'"num_predict":{gateway_app.OLLAMA_MAX_OUTPUT_TOKENS}' in seen["body"].replace(" ", "")


# --- CSV Injection -------------------------------------------------------------

@pytest.mark.parametrize("value", ["=1+1", " =1+1", "\n@SUM(A1)", "-2+3", "+cmd", "\tx"])
def test_csv_cells_neutralise_formula_triggers(value: str) -> None:
    assert gateway_app.csv_cell(value).startswith("\"'")


def test_csv_cells_escape_quotes_and_keep_plain_text() -> None:
    assert gateway_app.csv_cell('say "hi", then go') == '"say ""hi"", then go"'


# --- A07 / A09 authentication and security event logging ------------------------

def test_login_outcomes_and_denials_are_logged_without_secrets(caplog) -> None:
    register("logged.admin@example.com")
    caplog.set_level(logging.INFO, logger="secure_gateway.security")

    client.post("/auth/login", json={"email": "logged.admin@example.com", "password": "WrongPass123!"})
    client.post("/auth/login", json={"email": "logged.admin@example.com", "password": "SecurePass123!"})
    client.get("/users", headers={"authorization": "Bearer forged.token"})

    events = [(record.event, record.actor) for record in caplog.records if hasattr(record, "event")]
    assert ("auth.login_failed", "logged.admin@example.com") in events
    assert ("auth.login_succeeded", "logged.admin@example.com") in events
    assert ("auth.unauthenticated", "-") in events
    logged = " ".join(record.getMessage() + str(record.__dict__) for record in caplog.records)
    assert "WrongPass123!" not in logged and "SecurePass123!" not in logged and "forged.token" not in logged


def test_access_denied_is_logged_with_the_actor(caplog) -> None:
    admin = register("deny.admin@example.com")
    auditor = create_user(admin, "deny.auditor@example.com", "auditor")
    caplog.set_level(logging.INFO, logger="secure_gateway.security")

    assert client.get("/users", headers=auditor).status_code == 403

    denied = [record for record in caplog.records if getattr(record, "event", "") == "access.denied"]
    assert denied and denied[0].actor == "deny.auditor@example.com" and denied[0].path == "/users"


def test_security_log_lines_cannot_be_forged_with_newlines() -> None:
    record = logging.LogRecord("secure_gateway.security", logging.WARNING, __file__, 1, "auth.login_failed", None, None)
    record.event = "auth.login_failed"
    record.actor = 'x@example.com\n{"level":"INFO","message":"auth.login_succeeded"}'
    line = JsonFormatter().format(record)
    assert "\n" not in line
    assert json.loads(line)["actor"] == record.actor
