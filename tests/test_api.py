"""Tests for the local JSON API and employee web interface."""

from io import BytesIO
import json
import unittest

from app.api import MAX_REQUEST_BYTES, create_app
from app.auth import AuthService
from app.logging.audit_logger import AuditLogger
from app.prompt_gateway import PromptProcessingError
from app.providers.groq_provider import ProviderRequestError


class RecordingGateway:
    """Small deterministic gateway substitute for API boundary tests."""

    def __init__(self, *, failure: Exception | None = None) -> None:
        self.failure = failure
        self.calls: list[dict] = []

    def process_prompt(self, prompt: str, *, user_id: str, role: str) -> dict:
        self.calls.append(
            {"prompt": prompt, "user_id": user_id, "role": role}
        )

        if self.failure is not None:
            raise self.failure

        return {
            "decision": "ALLOW",
            "risk": {
                "score": 0,
                "level": "NONE",
                "reasons": ["No sensitive data detected."],
            },
            "policy": {
                "decision": "ALLOW",
                "risk_level": "NONE",
                "reason": "No sensitive data was detected.",
                "triggering_labels": [],
                "user_confirmation_required": False,
            },
            "detections": [],
            "sanitization": None,
            "prompt_for_external_ai": prompt,
            "audit_event": {
                "event_id": "00000000-0000-0000-0000-000000000001",
                "raw_prompt_stored": False,
            },
        }


class SanitizingGateway(RecordingGateway):
    def process_prompt(self, prompt: str, *, user_id: str, role: str) -> dict:
        result = super().process_prompt(prompt, user_id=user_id, role=role)
        result["decision"] = "SANITIZE"
        result["prompt_for_external_ai"] = "Contact [EMAIL_1]."
        return result


class BlockingGateway(RecordingGateway):
    def process_prompt(self, prompt: str, *, user_id: str, role: str) -> dict:
        result = super().process_prompt(prompt, user_id=user_id, role=role)
        result["decision"] = "BLOCK"
        result["prompt_for_external_ai"] = None
        return result


class RecordingAuthService:
    """Provide deterministic identities and sessions for API tests."""

    def __init__(self) -> None:
        self.valid_token = "fictional-session-token"
        self.identity = {
            "user_id": "EMP2048",
            "role": "EMPLOYEE",
            "expires_at": "2099-01-01T00:00:00+00:00",
        }
        self.logout_calls: list[str] = []

    def authenticate(self, user_id: str, password: str) -> dict:
        if user_id != "EMP2048" or password != "FictionalPass123!":
            from app.auth import InvalidCredentialsError

            raise InvalidCredentialsError("Invalid user ID or password.")

        return {
            "access_token": self.valid_token,
            "token_type": "Bearer",
            **self.identity,
        }

    def validate_session(self, token: str) -> dict:
        if token != self.valid_token:
            from app.auth import InvalidSessionError

            raise InvalidSessionError("Session is invalid or expired.")

        return self.identity.copy()

    def logout(self, token: str) -> None:
        self.validate_session(token)
        self.logout_calls.append(token)


class RecordingAuditLogger:
    """Return deterministic metadata for admin API tests."""

    def __init__(self) -> None:
        self.calls: list[dict] = []
        self.external_calls: list[dict] = []

    def query_events(self, **values) -> dict:
        self.calls.append(values)
        return {
            "events": [],
            "total": 0,
            "limit": values.get("limit", 25),
            "offset": values.get("offset", 0),
            "has_more": False,
            "summary": {
                "decisions": {"ALLOW": 0, "BLOCK": 0, "SANITIZE": 0},
                "risk_levels": {
                    "NONE": 0,
                    "LOW": 0,
                    "MEDIUM": 0,
                    "HIGH": 0,
                    "CRITICAL": 0,
                },
            },
        }

    def update_external_outcome(self, event_id: str, **values) -> dict:
        self.external_calls.append({"event_id": event_id, **values})
        return {
            "event_id": event_id,
            "external_provider": values["external_provider"],
            "success": values["success"],
            "failure_code": values.get("failure_code"),
            "raw_prompt_stored": False,
        }


class RecordingAIProvider:
    name = "groq"

    def __init__(self, *, failure: bool = False) -> None:
        self.failure = failure
        self.prompts: list[str] = []
        self.message_batches: list[list[dict[str, str]]] = []

    def generate(self, prompt: str) -> dict:
        return self.generate_messages([{"role": "user", "content": prompt}])

    def generate_messages(self, messages: list[dict[str, str]]) -> dict:
        self.message_batches.append([message.copy() for message in messages])
        self.prompts.append(messages[-1]["content"])

        if self.failure:
            raise ProviderRequestError("Fictional provider details")

        return {
            "provider": "groq",
            "model": "openai/gpt-oss-120b",
            "content": "Fictional generated response.",
            "usage": {
                "input_tokens": 10,
                "output_tokens": 5,
                "total_tokens": 15,
            },
        }


class PromptGatewayAPITests(unittest.TestCase):
    def request(
        self,
        app,
        method: str,
        path: str,
        payload: object | None = None,
        *,
        content_type: str = "application/json",
        content_length: str | None = None,
        token: str | None = "fictional-session-token",
        query_string: str = "",
    ) -> tuple[str, dict[str, str], dict]:
        body = b"" if payload is None else json.dumps(payload).encode("utf-8")
        captured: dict = {}

        def start_response(status: str, headers: list[tuple[str, str]]) -> None:
            captured["status"] = status
            captured["headers"] = dict(headers)

        environ = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "CONTENT_TYPE": content_type,
            "CONTENT_LENGTH": (
                str(len(body)) if content_length is None else content_length
            ),
            "wsgi.input": BytesIO(body),
            "QUERY_STRING": query_string,
        }

        if token is not None:
            environ["HTTP_AUTHORIZATION"] = f"Bearer {token}"

        response_body = b"".join(app(environ, start_response))
        return (
            captured["status"],
            captured["headers"],
            json.loads(response_body.decode("utf-8")),
        )

    def test_health_endpoint_does_not_load_default_gateway(self) -> None:
        app = create_app()

        status, headers, body = self.request(app, "GET", "/api/health")

        self.assertEqual(status, "200 OK")
        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["service"], "secure-ai-prompt-gateway")
        self.assertIsNone(app._gateway)
        self.assertIsNone(app._auth_service)
        self.assertIsNone(app._audit_logger)
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_homepage_is_served_without_loading_security_services(self) -> None:
        app = create_app()

        status, headers, body = self.raw_request(app, "GET", "/")

        self.assertEqual(status, "200 OK")
        self.assertEqual(headers["Content-Type"], "text/html; charset=utf-8")
        self.assertIn(b"Secure AI Prompt Gateway", body)
        self.assertIn(b'id="login-form"', body)
        self.assertIsNone(app._gateway)
        self.assertIsNone(app._auth_service)

    def test_static_assets_use_allowlist_and_security_headers(self) -> None:
        app = create_app()

        for path, content_type in (
            ("/styles.css", "text/css; charset=utf-8"),
            ("/app.js", "text/javascript; charset=utf-8"),
            ("/favicon.svg", "image/svg+xml"),
        ):
            with self.subTest(path=path):
                status, headers, body = self.raw_request(app, "GET", path)
                self.assertEqual(status, "200 OK")
                self.assertEqual(headers["Content-Type"], content_type)
                self.assertTrue(body)
                self.assertEqual(headers["X-Frame-Options"], "DENY")
                self.assertIn("default-src 'self'", headers["Content-Security-Policy"])

    def raw_request(
        self,
        app,
        method: str,
        path: str,
    ) -> tuple[str, dict[str, str], bytes]:
        captured: dict = {}

        def start_response(status: str, headers: list[tuple[str, str]]) -> None:
            captured["status"] = status
            captured["headers"] = dict(headers)

        environ = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "CONTENT_TYPE": "",
            "CONTENT_LENGTH": "0",
            "wsgi.input": BytesIO(b""),
        }
        body = b"".join(app(environ, start_response))
        return captured["status"], captured["headers"], body

    def test_process_endpoint_passes_valid_request_to_gateway(self) -> None:
        gateway = RecordingGateway()
        auth = RecordingAuthService()
        app = create_app(gateway=gateway, auth_service=auth)
        payload = {
            "prompt": "Explain fictional encryption architecture.",
        }

        status, headers, body = self.request(
            app,
            "POST",
            "/api/prompts/process",
            payload,
        )

        self.assertEqual(status, "200 OK")
        self.assertEqual(body["decision"], "ALLOW")
        self.assertIsNone(body["ai_response"])
        self.assertEqual(
            gateway.calls,
            [
                {
                    "prompt": payload["prompt"],
                    "user_id": "EMP2048",
                    "role": "EMPLOYEE",
                }
            ],
        )
        self.assertEqual(
            headers["Content-Type"],
            "application/json; charset=utf-8",
        )
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")

    def test_identity_and_role_come_from_authenticated_session(self) -> None:
        gateway = RecordingGateway()
        auth = RecordingAuthService()
        auth.identity["user_id"] = "ADMIN01"
        auth.identity["role"] = "ADMIN"
        app = create_app(gateway=gateway, auth_service=auth)

        status, _, _ = self.request(
            app,
            "POST",
            "/api/prompts/process",
            {
                "prompt": "A fictional clean prompt.",
            },
        )

        self.assertEqual(status, "200 OK")
        self.assertEqual(gateway.calls[0]["user_id"], "ADMIN01")
        self.assertEqual(gateway.calls[0]["role"], "ADMIN")

    def test_unknown_route_returns_json_404(self) -> None:
        app = create_app(gateway=RecordingGateway())

        status, _, body = self.request(app, "GET", "/missing")

        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body, {"error": "NOT_FOUND"})

    def test_wrong_method_returns_405_and_allow_header(self) -> None:
        app = create_app(gateway=RecordingGateway())

        status, headers, body = self.request(
            app,
            "GET",
            "/api/prompts/process",
        )

        self.assertEqual(status, "405 Method Not Allowed")
        self.assertEqual(headers["Allow"], "POST")
        self.assertEqual(body, {"error": "METHOD_NOT_ALLOWED"})

    def test_non_json_content_type_is_rejected(self) -> None:
        app = create_app(
            gateway=RecordingGateway(),
            auth_service=RecordingAuthService(),
        )

        status, _, body = self.request(
            app,
            "POST",
            "/api/prompts/process",
            {"prompt": "demo"},
            content_type="text/plain",
        )

        self.assertEqual(status, "415 Unsupported Media Type")
        self.assertEqual(body, {"error": "JSON_CONTENT_TYPE_REQUIRED"})

    def test_invalid_payloads_return_safe_400_error(self) -> None:
        invalid_payloads = (
            [],
            {},
            {"prompt": 123},
            {"prompt": "demo", "user_id": "FORGED01"},
            {"prompt": "demo", "role": "ADMIN"},
        )

        for payload in invalid_payloads:
            with self.subTest(payload=payload):
                app = create_app(
                    gateway=RecordingGateway(),
                    auth_service=RecordingAuthService(),
                )
                status, _, body = self.request(
                    app,
                    "POST",
                    "/api/prompts/process",
                    payload,
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body, {"error": "INVALID_REQUEST"})

    def test_malformed_json_returns_safe_400_error(self) -> None:
        app = create_app(
            gateway=RecordingGateway(),
            auth_service=RecordingAuthService(),
        )
        captured: dict = {}

        def start_response(status: str, headers: list[tuple[str, str]]) -> None:
            captured["status"] = status

        environ = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": "/api/prompts/process",
            "CONTENT_TYPE": "application/json",
            "CONTENT_LENGTH": "9",
            "wsgi.input": BytesIO(b"{invalid}"),
            "HTTP_AUTHORIZATION": "Bearer fictional-session-token",
        }

        body = b"".join(app(environ, start_response))

        self.assertEqual(captured["status"], "400 Bad Request")
        self.assertEqual(
            json.loads(body),
            {"error": "INVALID_REQUEST"},
        )

    def test_oversized_request_is_rejected_before_body_read(self) -> None:
        gateway = RecordingGateway()
        app = create_app(
            gateway=gateway,
            auth_service=RecordingAuthService(),
        )

        status, _, body = self.request(
            app,
            "POST",
            "/api/prompts/process",
            {},
            content_length=str(MAX_REQUEST_BYTES + 1),
        )

        self.assertEqual(status, "413 Payload Too Large")
        self.assertEqual(body, {"error": "REQUEST_TOO_LARGE"})
        self.assertEqual(gateway.calls, [])

    def test_processing_failure_does_not_expose_sensitive_details(self) -> None:
        secret = "FictionalSecretValue123"
        gateway = RecordingGateway(
            failure=PromptProcessingError(secret)
        )
        app = create_app(
            gateway=gateway,
            auth_service=RecordingAuthService(),
        )

        status, _, body = self.request(
            app,
            "POST",
            "/api/prompts/process",
            {"prompt": secret},
        )

        self.assertEqual(status, "500 Internal Server Error")
        self.assertEqual(body, {"error": "LOCAL_PROCESSING_ERROR"})
        self.assertNotIn(secret, str(body))

    def test_unexpected_failure_returns_generic_error(self) -> None:
        secret = "AnotherFictionalSecret456"
        gateway = RecordingGateway(failure=RuntimeError(secret))
        app = create_app(
            gateway=gateway,
            auth_service=RecordingAuthService(),
        )

        status, _, body = self.request(
            app,
            "POST",
            "/api/prompts/process",
            {"prompt": secret},
        )

        self.assertEqual(status, "500 Internal Server Error")
        self.assertEqual(body, {"error": "INTERNAL_SERVER_ERROR"})
        self.assertNotIn(secret, str(body))

    def test_login_returns_session_and_trusted_role(self) -> None:
        auth = RecordingAuthService()
        app = create_app(
            gateway=RecordingGateway(),
            auth_service=auth,
        )

        status, headers, body = self.request(
            app,
            "POST",
            "/api/auth/login",
            {
                "user_id": "EMP2048",
                "password": "FictionalPass123!",
            },
            token=None,
        )

        self.assertEqual(status, "200 OK")
        self.assertEqual(body["access_token"], auth.valid_token)
        self.assertEqual(body["role"], "EMPLOYEE")
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_invalid_login_uses_generic_credential_error(self) -> None:
        app = create_app(
            gateway=RecordingGateway(),
            auth_service=RecordingAuthService(),
        )

        status, headers, body = self.request(
            app,
            "POST",
            "/api/auth/login",
            {
                "user_id": "UNKNOWN01",
                "password": "WrongFictionalPass123!",
            },
            token=None,
        )

        self.assertEqual(status, "401 Unauthorized")
        self.assertEqual(body, {"error": "INVALID_CREDENTIALS"})
        self.assertEqual(headers["WWW-Authenticate"], "Bearer")
        self.assertNotIn("WrongFictionalPass123!", str(body))

    def test_prompt_endpoint_requires_valid_bearer_token(self) -> None:
        gateway = RecordingGateway()
        app = create_app(
            gateway=gateway,
            auth_service=RecordingAuthService(),
        )

        status, headers, body = self.request(
            app,
            "POST",
            "/api/prompts/process",
            {"prompt": "A fictional prompt."},
            token=None,
        )

        self.assertEqual(status, "401 Unauthorized")
        self.assertEqual(body, {"error": "AUTHENTICATION_REQUIRED"})
        self.assertEqual(headers["WWW-Authenticate"], "Bearer")
        self.assertEqual(gateway.calls, [])

    def test_logout_invalidates_supplied_session(self) -> None:
        auth = RecordingAuthService()
        app = create_app(
            gateway=RecordingGateway(),
            auth_service=auth,
        )

        status, _, body = self.request(
            app,
            "POST",
            "/api/auth/logout",
        )

        self.assertEqual(status, "200 OK")
        self.assertEqual(body, {"status": "logged_out"})
        self.assertEqual(auth.logout_calls, [auth.valid_token])

    def test_real_authentication_service_protects_prompt_request(self) -> None:
        auth = AuthService(":memory:", hash_iterations=1_000)
        self.addCleanup(auth.close)
        auth.create_user(
            "EMP2048",
            "FictionalPass123!",
            "EMPLOYEE",
        )
        gateway = RecordingGateway()
        app = create_app(gateway=gateway, auth_service=auth)

        login_status, _, login_body = self.request(
            app,
            "POST",
            "/api/auth/login",
            {
                "user_id": "EMP2048",
                "password": "FictionalPass123!",
            },
            token=None,
        )
        process_status, _, process_body = self.request(
            app,
            "POST",
            "/api/prompts/process",
            {"prompt": "Explain fictional encryption architecture."},
            token=login_body["access_token"],
        )

        self.assertEqual(login_status, "200 OK")
        self.assertEqual(process_status, "200 OK")
        self.assertEqual(process_body["decision"], "ALLOW")
        self.assertEqual(gateway.calls[0]["user_id"], "EMP2048")
        self.assertEqual(gateway.calls[0]["role"], "EMPLOYEE")

    def test_admin_can_query_privacy_safe_audit_metadata(self) -> None:
        auth = RecordingAuthService()
        auth.identity["user_id"] = "ADMIN01"
        auth.identity["role"] = "ADMIN"
        audit = RecordingAuditLogger()
        app = create_app(
            gateway=RecordingGateway(),
            auth_service=auth,
            audit_logger=audit,
        )

        status, _, body = self.request(
            app,
            "GET",
            "/api/admin/audit-events",
            query_string="limit=10&offset=5&decision=BLOCK",
        )

        self.assertEqual(status, "200 OK")
        self.assertEqual(body["events"], [])
        self.assertEqual(
            audit.calls,
            [{"limit": 10, "offset": 5, "decision": "BLOCK"}],
        )

    def test_employee_cannot_access_admin_audit_endpoint(self) -> None:
        audit = RecordingAuditLogger()
        app = create_app(
            gateway=RecordingGateway(),
            auth_service=RecordingAuthService(),
            audit_logger=audit,
        )

        status, _, body = self.request(
            app,
            "GET",
            "/api/admin/audit-events",
        )

        self.assertEqual(status, "403 Forbidden")
        self.assertEqual(body, {"error": "ADMIN_ROLE_REQUIRED"})
        self.assertEqual(audit.calls, [])

    def test_admin_audit_endpoint_requires_authentication(self) -> None:
        app = create_app(
            gateway=RecordingGateway(),
            auth_service=RecordingAuthService(),
            audit_logger=RecordingAuditLogger(),
        )

        status, _, body = self.request(
            app,
            "GET",
            "/api/admin/audit-events",
            token=None,
        )

        self.assertEqual(status, "401 Unauthorized")
        self.assertEqual(body, {"error": "AUTHENTICATION_REQUIRED"})

    def test_invalid_admin_query_is_rejected(self) -> None:
        auth = RecordingAuthService()
        auth.identity["role"] = "ADMIN"
        app = create_app(
            gateway=RecordingGateway(),
            auth_service=auth,
            audit_logger=RecordingAuditLogger(),
        )

        for query in ("limit=invalid", "unknown=value", "limit=1&limit=2"):
            with self.subTest(query=query):
                status, _, body = self.request(
                    app,
                    "GET",
                    "/api/admin/audit-events",
                    query_string=query,
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body, {"error": "INVALID_QUERY"})

    def test_real_admin_login_can_read_real_audit_metadata(self) -> None:
        auth = AuthService(":memory:", hash_iterations=1_000)
        audit = AuditLogger(":memory:")
        self.addCleanup(auth.close)
        self.addCleanup(audit.close)
        auth.create_user(
            "ADMIN01",
            "FictionalAdminPass123!",
            "ADMIN",
        )
        audit.log_event(
            user_id="EMP2048",
            role="EMPLOYEE",
            decision="SANITIZE",
            risk_level="MEDIUM",
            detected_labels={"EMAIL": 1},
            detector_sources=["regex"],
        )
        app = create_app(
            gateway=RecordingGateway(),
            auth_service=auth,
            audit_logger=audit,
        )

        login_status, _, login_body = self.request(
            app,
            "POST",
            "/api/auth/login",
            {
                "user_id": "ADMIN01",
                "password": "FictionalAdminPass123!",
            },
            token=None,
        )
        audit_status, _, audit_body = self.request(
            app,
            "GET",
            "/api/admin/audit-events",
            token=login_body["access_token"],
        )

        self.assertEqual(login_status, "200 OK")
        self.assertEqual(audit_status, "200 OK")
        self.assertEqual(audit_body["total"], 1)
        self.assertEqual(
            audit_body["events"][0]["detected_labels"],
            {"EMAIL": 1},
        )
        self.assertFalse(audit_body["events"][0]["raw_prompt_stored"])

    def test_only_sanitized_prompt_is_sent_to_external_provider(self) -> None:
        provider = RecordingAIProvider()
        audit = RecordingAuditLogger()
        app = create_app(
            gateway=SanitizingGateway(),
            auth_service=RecordingAuthService(),
            audit_logger=audit,
            ai_provider=provider,
        )

        status, _, body = self.request(
            app,
            "POST",
            "/api/prompts/process",
            {"prompt": "Contact fictional.user@example.org."},
        )

        self.assertEqual(status, "200 OK")
        self.assertEqual(provider.prompts, ["Contact [EMAIL_1]."])
        self.assertEqual(
            body["ai_response"]["content"],
            "Fictional generated response.",
        )
        self.assertEqual(audit.external_calls[0]["external_provider"], "groq")
        self.assertTrue(audit.external_calls[0]["success"])

    def test_blocked_prompt_never_reaches_external_provider(self) -> None:
        provider = RecordingAIProvider()
        audit = RecordingAuditLogger()
        app = create_app(
            gateway=BlockingGateway(),
            auth_service=RecordingAuthService(),
            audit_logger=audit,
            ai_provider=provider,
        )

        status, _, body = self.request(
            app,
            "POST",
            "/api/prompts/process",
            {"prompt": "Password = FictionalPass123!"},
        )

        self.assertEqual(status, "200 OK")
        self.assertEqual(body["decision"], "BLOCK")
        self.assertIsNone(body["ai_response"])
        self.assertEqual(provider.prompts, [])
        self.assertEqual(audit.external_calls, [])

    def test_empty_allowed_prompt_remains_local(self) -> None:
        provider = RecordingAIProvider()
        audit = RecordingAuditLogger()
        app = create_app(
            gateway=RecordingGateway(),
            auth_service=RecordingAuthService(),
            audit_logger=audit,
            ai_provider=provider,
        )

        status, _, body = self.request(
            app,
            "POST",
            "/api/prompts/process",
            {"prompt": ""},
        )

        self.assertEqual(status, "200 OK")
        self.assertIsNone(body["ai_response"])
        self.assertEqual(provider.prompts, [])
        self.assertEqual(audit.external_calls, [])

    def test_provider_failure_is_safe_and_audited(self) -> None:
        provider = RecordingAIProvider(failure=True)
        audit = RecordingAuditLogger()
        app = create_app(
            gateway=RecordingGateway(),
            auth_service=RecordingAuthService(),
            audit_logger=audit,
            ai_provider=provider,
        )

        status, _, body = self.request(
            app,
            "POST",
            "/api/prompts/process",
            {"prompt": "A fictional safe prompt."},
        )

        self.assertEqual(status, "502 Bad Gateway")
        self.assertEqual(body, {"error": "EXTERNAL_PROVIDER_ERROR"})
        self.assertFalse(audit.external_calls[0]["success"])
        self.assertEqual(
            audit.external_calls[0]["failure_code"],
            "EXTERNAL_PROVIDER_ERROR",
        )
        self.assertNotIn("Fictional provider details", str(body))

    def test_second_prompt_receives_temporary_conversation_context(self) -> None:
        provider = RecordingAIProvider()
        app = create_app(
            gateway=RecordingGateway(),
            auth_service=RecordingAuthService(),
            audit_logger=RecordingAuditLogger(),
            ai_provider=provider,
        )

        first_status, _, first = self.request(
            app,
            "POST",
            "/api/prompts/process",
            {"prompt": "Describe fictional Project Aurora."},
        )
        second_status, _, _ = self.request(
            app,
            "POST",
            "/api/prompts/process",
            {
                "prompt": "Summarize it in one sentence.",
                "conversation_id": first["conversation_id"],
            },
        )

        self.assertEqual(first_status, "200 OK")
        self.assertEqual(second_status, "200 OK")
        self.assertEqual(
            provider.message_batches[1],
            [
                {"role": "user", "content": "Describe fictional Project Aurora."},
                {"role": "assistant", "content": "Fictional generated response."},
                {"role": "user", "content": "Summarize it in one sentence."},
            ],
        )

    def test_sanitized_value_not_raw_value_enters_context(self) -> None:
        raw_value = "fictional.user@example.org"
        provider = RecordingAIProvider()
        app = create_app(
            gateway=SanitizingGateway(),
            auth_service=RecordingAuthService(),
            audit_logger=RecordingAuditLogger(),
            ai_provider=provider,
        )

        _, _, first = self.request(
            app,
            "POST",
            "/api/prompts/process",
            {"prompt": f"Contact {raw_value}."},
        )
        self.request(
            app,
            "POST",
            "/api/prompts/process",
            {
                "prompt": "Use that fictional contact.",
                "conversation_id": first["conversation_id"],
            },
        )

        rendered_context = str(provider.message_batches)
        self.assertIn("[EMAIL_1]", rendered_context)
        self.assertNotIn(raw_value, rendered_context)

    def test_clear_conversation_removes_context(self) -> None:
        provider = RecordingAIProvider()
        app = create_app(
            gateway=RecordingGateway(),
            auth_service=RecordingAuthService(),
            audit_logger=RecordingAuditLogger(),
            ai_provider=provider,
        )
        _, _, first = self.request(
            app,
            "POST",
            "/api/prompts/process",
            {"prompt": "Fictional first message."},
        )

        clear_status, _, clear_body = self.request(
            app,
            "POST",
            "/api/conversations/clear",
            {"conversation_id": first["conversation_id"]},
        )
        retry_status, _, retry_body = self.request(
            app,
            "POST",
            "/api/prompts/process",
            {
                "prompt": "Fictional follow-up.",
                "conversation_id": first["conversation_id"],
            },
        )

        self.assertEqual(clear_status, "200 OK")
        self.assertEqual(clear_body, {"status": "cleared"})
        self.assertEqual(retry_status, "400 Bad Request")
        self.assertEqual(retry_body, {"error": "INVALID_REQUEST"})
        self.assertEqual(len(provider.message_batches), 1)

    def test_new_conversation_requires_authentication(self) -> None:
        app = create_app(
            gateway=RecordingGateway(),
            auth_service=RecordingAuthService(),
        )

        status, _, body = self.request(
            app,
            "POST",
            "/api/conversations/new",
            {},
            token=None,
        )

        self.assertEqual(status, "401 Unauthorized")
        self.assertEqual(body, {"error": "AUTHENTICATION_REQUIRED"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
