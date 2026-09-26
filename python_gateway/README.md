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

## Security component

On the `shaheed` branch, this service also manages revocable sessions, roles, persistent versioned policies and one-time approval release. See [Component 3 setup and API contract](../docs/COMPONENT3_DEMO.md), [proposal section](../docs/COMPONENT3_PROPOSAL.md), and [verification record](../docs/COMPONENT3_VALIDATION.md).

From the repository root, provision the initial admin using `python -m python_gateway.bootstrap_admin`. This interactive command reads the password privately. Public registration never grants administrator access. Existing accounts and password hashes are preserved; existing sessions require a new login after upgrading.

Use `python -m unittest discover -s python_gateway/tests -v` from the repository root to run the isolated security tests. These tests do not use the working database or call an AI provider.
