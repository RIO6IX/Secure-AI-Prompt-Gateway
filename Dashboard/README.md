# Secure AI Prompt Gateway

Local company-style system for inspecting employee prompts before they are sent to external AI services or a local Ollama model.

## Component 01: Sensitive Data Detection Engine

This repository includes a production-style detection backend that identifies, classifies, validates, scores, and returns masked previews for sensitive data in prompts. The engine detects credentials, API keys, passwords, PII, financial identifiers, source-code exposure, and high-entropy secrets using layered regex rules, validators, context checks, and optional NLP support.

The implementation is local-first: no paid APIs, no external cloud detection calls, and no raw prompt persistence inside the detection endpoint. Gateway routes consume the detection result and replace detected sensitive spans with `****` before sending sanitized text to the local Ollama service.

## Component 04: Audit Logging & Security Dashboard

Component 04 is implemented with FastAPI, SQLite, and the dashboard UI. Every gateway inspection writes masked audit events into SQLite, including actor, department, service, action, status, risk, risk score, finding, category, policy rule, source, and prompt hash. Raw prompts are not stored in the audit table.

The dashboard and separate Audit Logs page read directly from the SQLite-backed FastAPI API. They provide live metrics, high-risk alerts, detected data categories, user activity, filtered audit log review, and CSV export. Admin and auditor roles can review audit records, while admin users can also create and delete local users.

## Problem Statement

Employees can accidentally paste credentials, PII, financial data, source code, and proprietary indicators into tools such as ChatGPT, Gemini, or Copilot. This creates confidentiality, privacy, compliance, and intellectual-property risk. OWASP also treats sensitive information disclosure as a major LLM application risk.

## Architecture

```mermaid
flowchart TD
    A["Employee Prompt"] --> B["FastAPI Input Validation"]
    B --> C["Unicode NFKC Preprocessing"]
    C --> D["Parallel Detection Modules"]
    D --> E["Regex Detector"]
    D --> F["Secret / Entropy Detector"]
    D --> G["Financial Detector"]
    D --> H["PII / NER Detector"]
    D --> I["Source-Code Detector"]
    E --> J["Validation Layer"]
    F --> J
    G --> J
    H --> J
    I --> J
    J --> K["Context Enhancer"]
    K --> L["Deduplication"]
    L --> M["Confidence Aggregator"]
    M --> N["Risk Classifier"]
    N --> O["Structured Detection Result"]
```

## Supported Detection

- Credentials: AWS keys, GitHub/GitLab tokens, Google API keys, Stripe keys, Slack tokens, JWTs, bearer tokens, passwords, DB connection strings, private-key headers, generic API keys, high-entropy secrets.
- PII: email, phone, person/location/organization via optional spaCy NER, IP addresses, URL credentials, Sri Lankan NIC old/new formats.
- Financial: Luhn-validated card numbers, contextual CVV, IBAN, SWIFT/BIC.
- Source code/IP: code-like blocks, SQL/config/IaC signals, internal/proprietary/confidential context.

## API

Backend root: `http://localhost:8000`

Detection endpoints:

- `POST /api/v1/detect`
- `POST /api/v1/detect/batch`
- `GET /api/v1/health`
- `GET /api/v1/ready`
- `GET /health`
- `GET /ready`
- `GET /metrics`

Example:

```powershell
curl.exe -X POST http://localhost:8000/api/v1/detect `
  -H "Content-Type: application/json" `
  -d "{\"prompt\":\"My AWS key is AKIAIOSFODNN7EXAMPLE and email is user@example.com\",\"language\":\"en\"}"
```

## Local Development

```powershell
cd "C:\Users\user\OneDrive\Desktop\Secure AI Prompt Gateway\Dashboard"
python -m pip install -r python_gateway\requirements.txt
python -m spacy download en_core_web_sm
cd python_gateway
python -m uvicorn app:app --reload --host 127.0.0.1 --port 8000
```

Frontend:

```powershell
cd "C:\Users\user\OneDrive\Desktop\Secure AI Prompt Gateway\Dashboard"
npm.cmd run dev
```

## Tests

```powershell
cd "C:\Users\user\OneDrive\Desktop\Secure AI Prompt Gateway\Dashboard"
python -m pytest python_gateway/tests
node --test tests/rendered-html.test.mjs
npm.cmd run build
```

## Docker

```powershell
cd "C:\Users\user\OneDrive\Desktop\Secure AI Prompt Gateway\Dashboard"
$env:JWT_SECRET = "replace-with-a-random-secret-at-least-32-characters"
$env:CORRELATION_SALT = "replace-with-a-random-correlation-salt"
docker build -t secure-ai-detection-engine .
docker compose up --build detection-engine
```

Optional Prometheus:

```powershell
docker compose --profile monitoring up --build
```

## Configuration

Copy `.env.example` for local overrides.

- `ENVIRONMENT=development` or `production`
- `JWT_SECRET=<random value with at least 32 characters>`
- `TOKEN_TTL_SECONDS=43200`
- `CORS_ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000`
- `DB_PATH=python_gateway/audit_logs.sqlite3`
- `MAX_PROMPT_CHARS=50000`
- `PASSWORD_MIN_LENGTH=12`
- `PASSWORD_PBKDF2_ITERATIONS=310000`
- `LOGIN_MAX_ATTEMPTS=5`
- `LOGIN_WINDOW_SECONDS=900`
- `MAX_PROMPT_LENGTH=50000`
- `MAX_BATCH_SIZE=100`
- `MAX_BATCH_TOTAL_CHARS=250000`
- `DEFAULT_MIN_CONFIDENCE=0.35`
- `ENTROPY_THRESHOLD=3.7`
- `ENABLE_NER=true`
- `ENABLE_METRICS=true`
- `SPACY_MODEL=en_core_web_sm`

## Production Hardening Checklist

Before using this in a real company environment:

- Set `ENVIRONMENT=production`.
- Set a unique `JWT_SECRET` with at least 32 random characters. Do not use the local development default.
- Set `CORRELATION_SALT` to a separate random value.
- Restrict `CORS_ALLOWED_ORIGINS` to the real frontend origin only.
- Store `DB_PATH` on a backed-up disk or mounted Docker volume.
- Run behind HTTPS through a reverse proxy such as Nginx, Caddy, or a company gateway.
- Keep Ollama bound to localhost or an internal private network.
- Use organization SSO/MFA for production identity if this becomes an enterprise deployment.
- Review audit retention, backup, and deletion policy with the organization.
- Rotate secrets immediately if a real credential is pasted into a prompt.

## Security and Privacy Design

- Detection-only API never forwards prompts to AI providers.
- Raw prompts and full matched values are not written to detection logs.
- Sensitive previews are masked.
- Auth, audit, report, and gateway responses include no-store cache headers.
- Browser-facing API responses include defensive security headers.
- CSV exports neutralize formula-like cells to reduce spreadsheet injection risk.
- Unicode is normalized with NFKC and null bytes are removed.
- Regex rules use bounded patterns to reduce ReDoS risk.
- Luhn validates card structure only; it does not prove a card is real.
- Sri Lankan NIC detection is stronger with NIC/identity context to reduce false positives.
- spaCy/Presidio are optional at runtime; if the model is missing, the backend remains healthy and marks NER unavailable.

## Current Dashboard Backend

The existing FastAPI service still supports:

- Login/register
- Role-based admin/auditor/user access
- Component 03 policy decisions: `ALLOW`, `SANITIZE`, and `BLOCK`
- Audit logs
- Dashboard summaries
- Prompt Monitor audit ingestion
- Filtered audit review and CSV export

The new detection API and Security Policy & Access Control Engine are mounted into that same service.

## Local Ollama Gateway

The root page is a secure chat gateway. It performs Component 01 detection, masks detected sensitive values with `****`, applies Component 03 Security Policy & Access Control decisions, forwards only allowed or sanitized prompts to Ollama, and writes Component 04 audit logs. Component 02 Prompt Sanitization & Risk Assessment remains an explicit extension point so the current deterministic masking stage can be replaced by the full risk-scoring component later.

Default model:

```powershell
ollama pull qwen2.5:3b
ollama serve
```

`qwen2.5:3b` is used because that model is installed on this local machine. Ollama's official Qwen2.5 library does not publish a `2b` tag. You can override it with `OLLAMA_MODEL`.

## Desktop App

Electron is configured as a local desktop wrapper for the same FastAPI and Vinext system.

Run in development:

```powershell
npm.cmd run electron
```

Build the Windows portable executable:

```powershell
npm.cmd run dist:electron
```

The current portable executable was built at:

```text
C:\Users\user\Downloads\SecureAI-PromptGateway-Desktop\Secure AI Prompt Gateway 0.1.0.exe
```

The desktop wrapper starts the local backend and frontend from this project folder. Keep Python, Node.js, and this project folder available on the machine.

## Known Limitations

- Regex cannot detect every unknown secret format.
- Entropy can produce false positives.
- NER quality depends on model and language.
- Source-code/IP detection needs organization-specific tuning for best accuracy.
- Local processing reduces exposure but cannot protect a compromised endpoint.
- This component is not a replacement for a complete enterprise DLP platform.

## Academic and Ethical Use

This project is for university information-security coursework and defensive software engineering. Use it only to protect systems you own or are authorized to test.

## Research References

- OWASP Top 10 for LLM Applications: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- Microsoft Presidio Analyzer: https://microsoft.github.io/presidio/analyzer/
- spaCy English models: https://spacy.io/models/en
- Prometheus client libraries: https://prometheus.io/docs/instrumenting/clientlibs/
