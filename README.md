# Secure AI Prompt Gateway

Local company-style system for detecting sensitive data in AI prompts, masking it, and storing audit logs in SQLite.

## Component 3 on the shaheed branch

Security policy, sessions, RBAC and approvals are documented in [Shaheed's proposal section](docs/COMPONENT3_PROPOSAL.md) and [setup, demonstration and integration guide](docs/COMPONENT3_DEMO.md).

The first administrator must be created locally with `python -m python_gateway.bootstrap_admin`. Public registration creates general users only. Existing users must sign in again after upgrading to the new session system. Use `/security` for prompt checks, approvals, password changes and policy administration. This branch does not send prompts to external AI providers.

## Database

This project uses **SQLite** through the FastAPI backend.

- Database file: `python_gateway/audit_logs.sqlite3`
- Tables created automatically: `users`, `audit_events`
- The frontend does not write to its own database. It reads/writes through FastAPI at `http://localhost:8000`.

## Local Hosting

Run the Python backend:

```powershell
cd "C:\Users\user\OneDrive\Desktop\Secure AI Prompt Gateway"
python -m pip install -r python_gateway\requirements.txt
npm run backend
```

Run the frontend in another terminal:

```powershell
cd "C:\Users\user\OneDrive\Desktop\Secure AI Prompt Gateway"
npm run dev
```

Open:

- Frontend dashboard: `http://localhost:3000`
- Register page: `http://localhost:3000/register`
- Login page: `http://localhost:3000/login`
- Backend health: `http://localhost:8000/health`

The frontend reads the local backend at `http://localhost:8000` by default. To use another backend URL, set `NEXT_PUBLIC_API_BASE_URL`.

## Backend Endpoints

- `POST /auth/register`
- `POST /auth/login`
- `GET /auth/me`
- `GET /audit`
- `POST /audit`
- `POST /inspect`
- `GET /audit/events`
- `GET /health`
 
## Roles

- `admin`: all privileges, including creating users and writing audit events
- `auditor`: read-only audit logs and report export
- `user`: submit prompts and manage own approval requests
- `approver`: submit prompts and review other users' approval requests

## Test Prompt

After registering, use **Prompt Monitor** or post to `/inspect` with a real prompt containing sensitive data. The backend masks values like API keys and stores only the masked output in audit logs.
