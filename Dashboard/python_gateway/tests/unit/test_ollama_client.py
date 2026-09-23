"""call_ollama reports each failure accurately instead of one generic message."""

import asyncio

import httpx
import pytest

import app as gateway_app


def run_with(monkeypatch, handler) -> tuple[str, bool]:
    transport = httpx.MockTransport(handler)
    real_client = httpx.AsyncClient

    def client_factory(*args, **kwargs):
        kwargs["transport"] = transport
        return real_client(*args, **kwargs)

    monkeypatch.setattr(gateway_app.httpx, "AsyncClient", client_factory)
    return asyncio.run(gateway_app.call_ollama("hello", [{"role": "user", "content": "earlier"}]))


def test_success_sends_history_to_the_chat_api(monkeypatch) -> None:
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["body"] = request.read().decode()
        return httpx.Response(200, json={"message": {"role": "assistant", "content": "hi there"}})

    assert run_with(monkeypatch, handler) == ("hi there", True)
    assert seen["path"] == "/api/chat"
    assert '"earlier"' in seen["body"] and '"hello"' in seen["body"]


@pytest.mark.parametrize("exception, expected", [
    (httpx.ReadTimeout("slow"), "did not answer within"),
    (httpx.ConnectError("refused"), "not reachable"),
])
def test_transport_failures_have_specific_messages(monkeypatch, exception, expected: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise exception

    message, available = run_with(monkeypatch, handler)
    assert expected in message and available is False
    assert "Sensitive data was detected" not in message


def test_missing_model_tells_the_admin_what_to_pull(monkeypatch) -> None:
    message, available = run_with(monkeypatch, lambda request: httpx.Response(404, json={"error": "model not found"}))
    assert "ollama pull" in message and available is False
