# Python Audit Logging Service

This FastAPI service is the backend foundation for the Secure AI Prompt Gateway.
It detects and masks sensitive prompt data, stores users and audit logs in local SQLite, and exposes the APIs used by the frontend.

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

SQLite database:

```text
python_gateway/audit_logs.sqlite3
```

The database and required tables are created automatically when FastAPI starts.
