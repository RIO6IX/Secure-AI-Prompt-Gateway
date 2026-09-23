# Secure AI Prompt Gateway

Local company-style system for inspecting employee prompts before they are sent to external AI services or a local Ollama model.

## Component 01: Sensitive Data Detection Engine

This repository includes a production-style detection backend that identifies, classifies, validates, scores, and returns masked previews for sensitive data in prompts. The engine detects credentials, API keys, passwords, PII, financial identifiers, source-code exposure, and high-entropy secrets using layered regex rules, validators, context checks, and optional NLP support.

The implementation is local-first: no paid APIs, no external cloud detection calls, and no raw prompt persistence inside the detection endpoint. Gateway routes pass the detection result to Component 02, which replaces the detected spans with typed placeholders before any text is sent to the local Ollama service.

## Component 02: Prompt Sanitization & Risk Assessment

Code lives in `python_gateway/prompt_sanitizer/`.

- **Sanitizer** (`sanitizer.py`): replaces each detected span with a typed, numbered placeholder such as `[EMAIL_ADDRESS_1]` or `[CREDIT_CARD_NUMBER_1]`. The same value always gets the same placeholder, so the model can still follow references. The placeholder-to-value map stays in memory for the request only. PII placeholders in the model's reply are restored for the user; credentials and card data never are. Low-risk place and company names are left in place, so ordinary questions stay readable.
- **Risk assessor** (`risk_assessment.py`): gives each entity type a weight (private key 80, cloud or API key 60, card 50, password 50, NIC 30, email 15, phone 10, location 5, and so on). The weight is scaled by detection confidence, with a smaller add-on for repeats and +10 for each extra data category in the same prompt. The score is capped at 100: LOW < 25 ≤ MEDIUM < 50 ≤ HIGH < 80 ≤ CRITICAL. The assessor recommends ALLOW, SANITIZE or BLOCK and lists the factors behind the score.
- **Tunable policy** (`risk_policy.py`): `RISK_POLICY_FILE` can override any entity weight, category default, threshold or bonus, so a bank can weight card data more heavily than a software house would. The file is validated strictly at startup. Unknown keys, weights outside 0-100 or thresholds that aren't increasing stop the service with a clear error, instead of mis-scoring prompts.
- **Repeated attempts**: each prompt from the same user that was blocked in the last `RISK_HISTORY_MINUTES` adds 10 points to their next *sensitive* prompt, up to +30. This catches someone trying variations of a secret until one gets through. Clean prompts are never penalised.
- **Rate limit**: `/gateway/chat`, `/api/v1/sanitize` and `/inspect` accept `PROMPT_RATE_LIMIT_PER_MINUTE` requests per user. Beyond that they return HTTP 429 with a `Retry-After` header.
- **Conversations** (`conversation.py`): the chat keeps context between messages. The model receives the *sanitized* history through Ollama's chat API. A conversation-wide `PseudonymMap` gives each value the same placeholder in every turn, and a new value never reuses an earlier number. The map stores keyed HMAC hashes rather than plaintext values. Conversations belong to one user, live only in memory, expire when idle and can be ended with `DELETE /gateway/conversations/{id}`. A blocked prompt never enters the history.
- **Reply guard** (`response_guard.py`): the model's reply is checked before anyone sees it. Placeholders the model repeats, even rewritten ones like `[Email_Address_1]`, are replaced with masked previews (`n***@company.lk`, `**** **** **** 6467`). Keys, passwords, card numbers and other sensitive values the model generates itself are masked too, and counted in the audit record. This addresses OWASP LLM02 (sensitive information disclosure).
- **Decision**: the gateway applies the stricter of the Component 02 risk recommendation and the Component 03 policy decision. A prompt that is only "sanitize" under each rule is still blocked when the combined risk is critical, for example a card, NIC, IBAN and contact details for one customer.

The browser extension in `../browser-extension` uses `POST /api/v1/sanitize` to apply the same pipeline to ChatGPT, Gemini, Copilot, Claude and Perplexity. See its README for installation.

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

- **Credentials:**
  - Cloud and AI provider keys: AWS access key and secret key, Azure Storage account key, GCP service-account key ID, OpenAI, Anthropic, Hugging Face and Google API keys.
  - Developer and messaging tokens: GitHub, GitLab, Stripe, Slack tokens and webhooks, SendGrid, npm, Telegram bot tokens.
  - JWTs and bearer tokens.
  - Passwords, including `key=value`, env-style (`DB_PASSWORD=`) and JSON forms.
  - Database connection strings.
  - Complete PEM, PKCS#8, OpenSSH and PGP private-key blocks.
  - Generic API keys, and high-entropy secrets that have no fixed format.
- **PII:** email addresses, phone numbers, Sri Lankan NIC numbers (old and new formats, with birth-date validation), passport numbers and dates of birth (both only next to a context word), IP addresses, URLs with embedded credentials, and person, location and organisation names found by spaCy NER.
- **Financial:** card numbers checked with the Luhn algorithm (separated by spaces, hyphens or dots), CVV next to a context word, IBAN with the mod-97 checksum, and SWIFT/BIC next to a context word.
- **Source code / IP:** code-like blocks, SQL, config and infrastructure-as-code signals, and "internal", "proprietary" or "confidential" wording.
- **Evasion resistance:** zero-width and other invisible Unicode characters are removed, and full-width characters are normalised (NFKC), before matching.

Accuracy and latency are measured by a labelled benchmark (`python -m evaluation.run`). See [docs/detection-engine-evaluation.md](docs/detection-engine-evaluation.md).

## API

Backend root: `http://localhost:8000`

Detection endpoints:

- `POST /api/v1/detect`
- `POST /api/v1/detect/batch`
- `POST /api/v1/sanitize` (login required; used by the browser extension)
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

Copy `.env.example` to `.env` and pass it to uvicorn with `--env-file ../.env`. The file lists every setting with its default. The most important ones:

- `ENVIRONMENT=development` or `production`
- `JWT_SECRET=<random value with at least 32 characters>`
- `TOKEN_TTL_SECONDS=43200`
- `CORS_ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000`
- `DB_PATH` (default `python_gateway/audit_logs.sqlite3`; use an absolute path when overriding)
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
- `RISK_HISTORY_MINUTES=60` (recent blocked prompts raise the next sensitive prompt's risk)
- `REPLY_PII_MODE=mask` (`mask` shows n***@company.lk in model replies, `restore` shows the requester's own values)
- `RISK_POLICY_FILE` (optional JSON overriding risk weights and thresholds; see `python_gateway/risk_policy.example.json`)
- `CONVERSATION_TTL_MINUTES=30`, `CONVERSATION_MAX_MESSAGES=20` (in-memory chat context)
- `PROMPT_RATE_LIMIT_PER_MINUTE=60` (per-user limit on the prompt endpoints, HTTP 429 beyond it)
- `NER_MAX_CHARS=20000` (NER coverage cap; regex, checksum and entropy rules always scan the whole prompt)

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

The root page is a secure chat gateway. For every prompt it runs Component 01 detection, Component 02 sanitization and risk scoring, and Component 03 policy. It forwards only the placeholder version of an allowed or sanitized prompt to Ollama, and writes one Component 04 audit record per prompt.

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
