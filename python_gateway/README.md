# Python Audit Logging Service

This service is the Python backend foundation for module 4 of the Secure AI Prompt Gateway.
It detects and masks sensitive prompt data, stores a local SQLite audit copy, and posts each audit event into the hosted dashboard backend.

Run locally:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app:app --reload --port 8000
```

Useful endpoints:

- `GET /health`
- `POST /inspect` detects sensitive data, masks it, and writes an audit event
- `POST /audit/events` writes a prebuilt audit event
- `GET /audit/events` reads the local Python service audit copy

The hosted backend URL defaults to:

```text
https://secure-ai-prompt-gateway.rio6ix.chatgpt.site/api/audit
```

Override it with `REMOTE_AUDIT_API_URL` when deploying to a different dashboard URL.
