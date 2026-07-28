# Python Audit Logging Service

This service is the Python backend foundation for module 4 of the Secure AI Prompt Gateway.
It stores prompt gateway decisions in SQLite and exposes APIs for the dashboard and future browser extension.

Run locally:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app:app --reload --port 8000
```

Useful endpoints:

- `GET /health`
- `GET /audit/events`
- `POST /audit/events`

