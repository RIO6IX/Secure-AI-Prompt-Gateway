# OWASP Controls in the Secure AI Prompt Gateway

This maps the OWASP guidance the gateway follows to the code that implements
it and the tests that prove it. Code references are to
`python_gateway/app.py` unless another file is named.

Guidance covered:

- OWASP Top 10 for LLM Applications 2025: LLM02, LLM05, LLM10
- OWASP Top 10 2021: A01, A02, A03, A05, A07, A09
- OWASP Logging Cheat Sheet and OWASP CSV Injection

Tests: `tests/integration/test_owasp_controls.py` holds one regression test per
control added for this mapping; the other tests named below already existed.

## LLM Top 10 2025

### LLM02 Sensitive Information Disclosure

| Control | Where |
|---|---|
| Every prompt is scanned (regex, checksum, entropy and NER detectors) before it can leave the gateway | `evaluate_prompt`, `detection_engine/` |
| Only the placeholder version (`[EMAIL_ADDRESS_1]`, `[AWS_ACCESS_KEY_1]`) is sent to the model; the original text never is | `gateway_chat`, `prompt_sanitizer/sanitizer.py` |
| Conversation history sent to the model is the sanitized history; a value keeps the same placeholder for the whole chat | `prompt_sanitizer/conversation.py` |
| The placeholder map stores keyed HMAC-SHA256 hashes with a random per-map key, not plaintext values | `PseudonymMap` |
| Model replies are scanned again; secrets the model produces are masked before display, and credentials are never restored into a reply | `prompt_sanitizer/response_guard.py`, `REPLY_PII_MODE` |
| The system prompt tells the model never to ask for or reconstruct redacted values | `call_ollama` |
| `SENSITIVE_DATA_ACTION=block` refuses to forward credentials or critical-risk prompts at all | `security_policy/engine.py` |
| Invisible Unicode is stripped and a worst-case input guard bounds regex cost, so evasion does not bypass detection | `detection_engine/core/security.py`, `tests/unit/test_evasion.py`, `tests/unit/test_redos_guard.py` |

### LLM05 Improper Output Handling

| Control | Where |
|---|---|
| Model output is treated as untrusted data: React renders it as text (no `dangerouslySetInnerHTML` anywhere in the app) | `app/components/SecureGatewayChat.tsx` |
| The browser extension writes every gateway value with `textContent` inside a closed shadow root | `browser-extension/content.js`, `popup.js` |
| Output is never executed, evaluated or used to build SQL, shell commands or URLs | whole backend |
| Sensitive values in the output are masked before the reply is returned or audited | `ResponseGuard.guard` |
| Gateway errors (Ollama down, model not pulled, timeout) are returned as a separate `modelError`, never mixed into model output | `gateway_chat`, `modelStatus` |

### LLM10 Unbounded Consumption

| Control | Setting / where |
|---|---|
| Maximum prompt size | `MAX_PROMPT_CHARS` (50 000) |
| Per-user prompt rate limit on chat and sanitize endpoints | `PROMPT_RATE_LIMIT_PER_MINUTE` (60), `SlidingWindowLimiter` |
| Cap on generated tokens per reply (new) | `OLLAMA_MAX_OUTPUT_TOKENS` (1024, sent as `num_predict`) |
| Cap on concurrent model generations across all users (new) | `OLLAMA_MAX_CONCURRENT` (2) |
| Model read timeout, short connect timeout | `OLLAMA_TIMEOUT_SECONDS` (180), 5 s connect |
| Bounded conversation length and idle expiry | `CONVERSATION_MAX_MESSAGES` (20), `CONVERSATION_TTL_MINUTES` (30) |
| NER only runs over a bounded prefix of the prompt | `NER_MAX_CHARS` |
| Length limits on free-text metadata fields and on passwords (PBKDF2 cost) (new) | Pydantic `max_length` on request models |

## Top 10 2021

### A01 Broken Access Control

- Every data endpoint requires a signed bearer token (`get_auth_user`), and roles are enforced server-side (`require_role`):
  - `admin`: prompts, users, audit, export.
  - `user`: prompts only.
  - `auditor`: audit and export only, and cannot send prompts (`POL-RBAC-001`).
- **New:** `GET /audit` returns the whole organisation's data only to admins and auditors. A plain user only sees their own prompts, and the `actor` filter cannot widen that.
- Conversations belong to the user who started them. Another user gets 404 (`ConversationStore.open`).
- Admins cannot delete their own account.

### A02 Cryptographic Failures

- Passwords: PBKDF2-HMAC-SHA256, 310 000 iterations, random salt per user (`password_hash`). Legacy hashes still verify.
- Tokens: HMAC-SHA256 signed with an expiry, compared in constant time (`hmac.compare_digest`). The app refuses to start in production with the default secret or a secret under 32 characters (`validate_runtime_config`).
- Raw prompts are never stored: the audit log keeps a SHA-256 hash of the prompt plus the masked text.
- **New:** `Strict-Transport-Security` is sent in production. TLS itself is terminated by the reverse proxy (see README deployment notes).

### A03 Injection

- All SQL uses bound parameters. Dynamic `WHERE` clauses are built from fixed column fragments only (`audit_filters`).
- Request bodies are validated by Pydantic models, and a malformed body gets 422.
- **New:** length limits on `service`, `department`, `source`, `name`, `email` and `password`.
- CSV export injection is covered under CSV Injection below.

### A05 Security Misconfiguration

- Headers:
  - `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, a restrictive `Permissions-Policy`.
  - `Cache-Control: no-store` on authenticated routes.
  - **New:** `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`.
- CORS is an explicit allow-list (`CORS_ALLOWED_ORIGINS`) and does not allow credentials.
- **New:** `/docs`, `/redoc` and `/openapi.json` are disabled when `ENVIRONMENT=production`.
- **New:** the unauthenticated `/health` endpoint only reports whether SIEM forwarding is configured, not the SIEM URL.
- Invalid risk-policy files, token or concurrency limits, and `SENSITIVE_DATA_ACTION` values stop the service at startup instead of running misconfigured.

### A07 Identification and Authentication Failures

- Password policy: at least 12 characters and at least three character classes (`validate_password_strength`).
- Login throttling: 5 failures per email and IP within 15 minutes returns 429 (`enforce_login_throttle`).
- A failed login gives the same message whether the email exists or not.
- Tokens expire after `TOKEN_TTL_SECONDS` (12 h by default).
- **New:** failed, successful and locked-out logins are logged (see A09).

### A09 Security Logging and Monitoring Failures

- **Audit trail:**
  - Every prompt writes one audit record: who, service, decision, risk, finding, masked text, prompt hash.
  - The record is re-scanned at the write boundary so raw secrets can never be stored (`harden_audit_event`).
  - Records can be forwarded to a SIEM (`REMOTE_AUDIT_API_URL`); a SIEM outage never loses the local record.
- **New security event log** (`security_event`, logger `secure_gateway.security`):

  | Event | When |
  |---|---|
  | `auth.login_succeeded` / `auth.login_failed` / `auth.login_locked` | Login outcomes |
  | `auth.registered` | Self-registration |
  | `admin.user_created` / `admin.user_deleted` | User management, with the acting admin and the target |
  | `auth.unauthenticated` (401), `access.denied` (403), `rate_limited` (429) | Any denied request, with actor, path, method and client IP |

- Metrics for monitoring are exposed at `/metrics` (Prometheus).

## Logging Cheat Sheet

- Each entry records when, where (path, method, client IP), who (actor) and outcome (event, status).
- It never records passwords, tokens or prompt text:
  - `PrivacyFilter` blanks fields named `prompt`, `password`, `token` and similar.
  - Security events only carry the whitelisted fields.
  - Tests assert that a wrong password and a forged token do not appear in the log.
- Log injection: entries are written as JSON (`JsonFormatter`), so CR/LF in a user-supplied value is escaped and cannot forge a new log line. This is tested.
- Audit records store masked text only and are sanitized again at the write boundary.

## CSV Injection

`csv_cell` is used for every cell of `/reports/export`:

- A cell whose first character is `=`, `+`, `-`, `@`, tab or CR gets a leading `'`.
- **New:** the same applies when the trigger is hidden behind leading spaces or line breaks.
- Every cell is wrapped in double quotes, and embedded quotes are doubled, so commas and semicolons cannot start new cells.

## Residual risks

- Tokens are stateless, so logout does not revoke a token before it expires. Keep `TOKEN_TTL_SECONDS` short in production.
- Self-registration reports "email is already registered", which reveals which accounts exist. Disable open registration in production if that matters.
- Detection is pattern- and model-based. An unusual secret format can still be missed, so `SENSITIVE_DATA_ACTION=block` is the safer choice where any leak is unacceptable.
