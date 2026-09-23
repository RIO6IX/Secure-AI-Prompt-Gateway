from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import sqlite3
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from uuid import uuid4

import httpx
from fastapi import FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from detection_engine.api.dependencies import get_detection_engine
from detection_engine.api.routes import router as detection_router
from detection_engine.api.routes import root_metrics, root_ready
from detection_engine.core.exceptions import DetectionError
from detection_engine.core.logging import configure_logging
from detection_engine.models.request import DetectRequest
from detection_engine.models.response import DetectedEntity, DetectionResponse
from detection_engine.services.health_service import health_payload


LOGGER = logging.getLogger("secure_gateway")

RiskLevel = Literal["Low", "Medium", "High", "Critical"]
Role = Literal["admin", "auditor", "user"]

BASE_DIR = Path(__file__).resolve().parent
ENVIRONMENT = os.getenv("ENVIRONMENT", "development").strip().lower()
DB_PATH = Path(os.getenv("DB_PATH", str(BASE_DIR / "audit_logs.sqlite3")))
REMOTE_AUDIT_API_URL = os.getenv(
    "REMOTE_AUDIT_API_URL",
    "",
)
REMOTE_AUDIT_BEARER_TOKEN = os.getenv("REMOTE_AUDIT_BEARER_TOKEN", "")
JWT_SECRET = os.getenv("JWT_SECRET", "local-dev-change-this-secret")
TOKEN_TTL_SECONDS = int(os.getenv("TOKEN_TTL_SECONDS", str(60 * 60 * 12)))
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:3b")
MAX_PROMPT_CHARS = int(os.getenv("MAX_PROMPT_CHARS", "50000"))
PASSWORD_MIN_LENGTH = int(os.getenv("PASSWORD_MIN_LENGTH", "12"))
PASSWORD_PBKDF2_ITERATIONS = int(os.getenv("PASSWORD_PBKDF2_ITERATIONS", "310000"))
LOGIN_MAX_ATTEMPTS = int(os.getenv("LOGIN_MAX_ATTEMPTS", "5"))
LOGIN_WINDOW_SECONDS = int(os.getenv("LOGIN_WINDOW_SECONDS", "900"))
CORS_ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("CORS_ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",")
    if origin.strip()
]

@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    configure_logging()
    validate_runtime_config()
    init_db()
    yield


app = FastAPI(
    title="Secure AI Prompt Gateway Python Service",
    version="0.2.0",
    description="Python gateway service that masks sensitive prompt data and writes real audit events.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)
app.include_router(detection_router)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("x-content-type-options", "nosniff")
    response.headers.setdefault("x-frame-options", "DENY")
    response.headers.setdefault("referrer-policy", "no-referrer")
    response.headers.setdefault("permissions-policy", "camera=(), microphone=(), geolocation=()")
    if request.url.path.startswith(("/auth", "/audit", "/reports", "/gateway")):
        response.headers.setdefault("cache-control", "no-store")
    return response


class RegisterIn(BaseModel):
    name: str = Field(..., examples=["Security Admin"])
    email: str = Field(..., examples=["sec.admin@company.com"])
    password: str = Field(..., min_length=8)


class CreateUserIn(RegisterIn):
    role: Role = "user"


class LoginIn(BaseModel):
    email: str
    password: str


class AuthOut(BaseModel):
    token: str
    user: dict[str, str]


class PromptInspectionIn(BaseModel):
    department: str = "Unknown"
    service: str = Field(..., examples=["ChatGPT Enterprise"])
    prompt: str = Field(..., max_length=MAX_PROMPT_CHARS)
    source: str = "python-gateway"


class GatewayPromptIn(BaseModel):
    prompt: str = Field(
        ...,
        min_length=1,
        max_length=MAX_PROMPT_CHARS,
        examples=["Please fix this API issue. My API key is sk_live_ABC123456789"],
    )
    service: str = "Ollama Qwen2.5"
    department: str = "Engineering"
    source: str = "secure-chat-gateway"
    forward_to_ollama: bool = True


class GatewayEntityOut(BaseModel):
    entityType: str
    category: str
    maskedValue: str
    riskLevel: str
    confidence: float
    start: int
    end: int


class GatewayPromptOut(BaseModel):
    requestId: str
    userPrompt: str
    sanitizedPrompt: str
    assistantMessage: str
    policyDecision: str
    actionTaken: str
    riskLevel: str
    riskScore: float
    containsSensitiveData: bool
    detectedEntities: list[GatewayEntityOut]
    auditEvents: list[dict[str, object]]
    ollamaModel: str
    ollamaAvailable: bool
    componentExtensionPoints: dict[str, str]
    componentPlaceholders: dict[str, str]


class AuditEventIn(BaseModel):
    actor: str
    department: str = "Unknown"
    service: str
    action: str
    status: str
    risk: RiskLevel
    riskScore: int
    finding: str
    category: str
    policyRule: str
    maskedOutput: str
    originalPrompt: str | None = None
    promptHash: str | None = None
    source: str = "python-gateway"


class AuditEvent(AuditEventIn):
    id: str
    timestamp: str
    remoteId: str | None = None


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def sign_token(payload: dict[str, str | int]) -> str:
    encoded = b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signature = hmac.new(JWT_SECRET.encode("utf-8"), encoded.encode("utf-8"), hashlib.sha256).digest()
    return f"{encoded}.{b64url(signature)}"


def verify_token(token: str) -> dict[str, str | int] | None:
    try:
        encoded, signature = token.split(".", 1)
        expected = b64url(hmac.new(JWT_SECRET.encode("utf-8"), encoded.encode("utf-8"), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            return None
        padded = encoded + "=" * (-len(encoded) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("utf-8")))
        if int(payload.get("exp", 0)) < int(time.time()):
            return None
        return payload
    except Exception:
        return None


def password_hash(password: str, salt: str | None = None) -> str:
    salt = salt or uuid4().hex
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PASSWORD_PBKDF2_ITERATIONS,
    ).hex()
    return f"pbkdf2_sha256${PASSWORD_PBKDF2_ITERATIONS}${salt}${digest}"


def check_password(password: str, stored: str) -> bool:
    parts = stored.split("$")
    if len(parts) == 4 and parts[0] == "pbkdf2_sha256":
        _, iterations, salt, digest = parts
        candidate = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            int(iterations),
        ).hex()
        return hmac.compare_digest(candidate, digest)
    if len(parts) == 2:
        salt, digest = parts
        legacy_digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120_000).hex()
        current_digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            PASSWORD_PBKDF2_ITERATIONS,
        ).hex()
        return hmac.compare_digest(legacy_digest, digest) or hmac.compare_digest(current_digest, digest)
    return False


def get_auth_user(authorization: str | None) -> dict[str, str]:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Login required")
    payload = verify_token(authorization.split(" ", 1)[1])
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired login")
    return {"email": str(payload["email"]), "name": str(payload["name"]), "role": normalize_role(str(payload["role"]))}


def normalize_role(role: str) -> Role:
    normalized = role.strip().lower().replace("security admin", "admin")
    if normalized in ("admin", "auditor", "user"):
        return normalized  # type: ignore[return-value]
    return "user"


def require_role(current_user: dict[str, str], allowed: set[Role]) -> None:
    if normalize_role(current_user["role"]) not in allowed:
        raise HTTPException(status_code=403, detail="You do not have permission for this action")


def validate_runtime_config() -> None:
    if ENVIRONMENT in {"production", "prod"} and JWT_SECRET == "local-dev-change-this-secret":
        raise RuntimeError("JWT_SECRET must be changed before running in production")
    if ENVIRONMENT in {"production", "prod"} and len(JWT_SECRET) < 32:
        raise RuntimeError("JWT_SECRET must be at least 32 characters in production")
    if not CORS_ALLOWED_ORIGINS:
        raise RuntimeError("CORS_ALLOWED_ORIGINS must contain at least one allowed origin")


def validate_password_strength(password: str) -> None:
    if len(password) < PASSWORD_MIN_LENGTH:
        raise HTTPException(status_code=400, detail=f"password must be at least {PASSWORD_MIN_LENGTH} characters")
    checks = [
        any(character.islower() for character in password),
        any(character.isupper() for character in password),
        any(character.isdigit() for character in password),
        any(not character.isalnum() for character in password),
    ]
    if sum(checks) < 3:
        raise HTTPException(status_code=400, detail="password must include at least three character types")


login_failures: dict[str, list[float]] = {}


def login_throttle_key(email: str, request: Request) -> str:
    host = request.client.host if request.client else "unknown"
    return f"{host}:{email.strip().lower()}"


def prune_login_failures(key: str) -> list[float]:
    cutoff = time.time() - LOGIN_WINDOW_SECONDS
    attempts = [attempt for attempt in login_failures.get(key, []) if attempt >= cutoff]
    if attempts:
        login_failures[key] = attempts
    else:
        login_failures.pop(key, None)
    return attempts


def enforce_login_throttle(email: str, request: Request) -> str:
    key = login_throttle_key(email, request)
    attempts = prune_login_failures(key)
    if len(attempts) >= LOGIN_MAX_ATTEMPTS:
        raise HTTPException(status_code=429, detail="Too many failed login attempts. Try again later.")
    return key


def record_failed_login(key: str) -> None:
    attempts = prune_login_failures(key)
    attempts.append(time.time())
    login_failures[key] = attempts


def clear_failed_logins(key: str) -> None:
    login_failures.pop(key, None)


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA busy_timeout = 10000")
    return connection


def init_db() -> None:
    with connect() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
              id TEXT PRIMARY KEY,
              name TEXT NOT NULL,
              email TEXT NOT NULL UNIQUE,
              password_hash TEXT NOT NULL,
              role TEXT NOT NULL DEFAULT 'Security Admin',
              created_at TEXT NOT NULL
            )
            """
        )
        connection.execute("UPDATE users SET role = 'admin' WHERE lower(role) IN ('security admin', 'administrator')")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_events (
              id TEXT PRIMARY KEY,
              timestamp TEXT NOT NULL,
              actor TEXT NOT NULL,
              department TEXT NOT NULL,
              service TEXT NOT NULL,
              action TEXT NOT NULL,
              status TEXT NOT NULL,
              risk TEXT NOT NULL,
              risk_score INTEGER NOT NULL,
              finding TEXT NOT NULL,
              category TEXT NOT NULL,
              policy_rule TEXT NOT NULL,
              masked_output TEXT NOT NULL,
              prompt_hash TEXT NOT NULL,
              source TEXT NOT NULL,
              remote_id TEXT
            )
            """
        )


def auth_response(row: sqlite3.Row) -> AuthOut:
    role = normalize_role(row["role"])
    user = {"name": row["name"], "email": row["email"], "role": role}
    token = sign_token({
        "name": row["name"],
        "email": row["email"],
        "role": role,
        "exp": int(time.time()) + TOKEN_TTL_SECONDS,
    })
    return AuthOut(token=token, user=user)


POLICY_BY_CATEGORY = {
    "CREDENTIAL": "Block credentials and tokens",
    "FINANCIAL": "Mask PCI data before AI submission",
    "PII": "Mask PII before AI submission",
    "SOURCE_CODE": "Warn on source code or internal URLs",
}
RISK_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def primary_entity(detection: DetectionResponse) -> DetectedEntity:
    """The finding that drives the audit record: highest risk, then confidence."""
    return max(
        detection.detected_entities,
        key=lambda entity: (RISK_RANK[entity.risk_level.value], entity.confidence),
    )


def entity_label(entity_type: str) -> str:
    return entity_type.replace("_", " ").title()


def inspect_prompt(payload: PromptInspectionIn, actor: str) -> AuditEventIn:
    detection = get_detection_engine().detect(DetectRequest(prompt=payload.prompt))
    masked = redact_from_detection(payload.prompt, detection)
    prompt_hash = hashlib.sha256(payload.prompt.encode("utf-8")).hexdigest()

    if not detection.contains_sensitive_data:
        return AuditEventIn(
            actor=actor,
            department=payload.department,
            service=payload.service,
            action="Prompt allowed",
            status="Allowed",
            risk="Low",
            riskScore=0,
            finding="No sensitive data detected",
            category="Clean",
            policyRule="Default prompt leakage policy",
            maskedOutput=masked,
            promptHash=prompt_hash,
            source=payload.source,
        )

    primary = primary_entity(detection)
    credential_hit = any(
        entity.category.value == "CREDENTIAL" and entity.risk_level.value in {"HIGH", "CRITICAL"}
        for entity in detection.detected_entities
    )
    return AuditEventIn(
        actor=actor,
        department=payload.department,
        service=payload.service,
        action="Prompt blocked" if credential_hit else "Prompt sanitized",
        status="Blocked" if credential_hit else "Sanitized",
        risk=title_case_risk(detection.overall_risk.value),
        riskScore=int(round(detection.risk_score * 100)),
        finding=entity_label(primary.entity_type),
        category=primary.category.value,
        policyRule=POLICY_BY_CATEGORY.get(primary.category.value, "Default prompt leakage policy"),
        maskedOutput=masked,
        promptHash=prompt_hash,
        source=payload.source,
    )


def redact_from_detection(prompt: str, detection: DetectionResponse) -> str:
    sanitized = prompt
    for entity in sorted(detection.detected_entities, key=lambda item: item.start, reverse=True):
        replacement = "****"
        sanitized = sanitized[: entity.start] + replacement + sanitized[entity.end :]
    return sanitized


def sanitize_audit_output(value: str) -> tuple[str, DetectionResponse | None]:
    if not value.strip():
        return value, None
    try:
        detection = get_detection_engine().detect(DetectRequest(prompt=value))
    except DetectionError:
        return value, None
    if not detection.contains_sensitive_data:
        return value, detection
    return redact_from_detection(value, detection), detection


def harden_audit_event(event: AuditEventIn) -> AuditEventIn:
    sanitized_output, detection = sanitize_audit_output(event.maskedOutput)
    if not detection or not detection.contains_sensitive_data:
        return event

    updates: dict[str, object] = {"maskedOutput": sanitized_output}
    if sanitized_output != event.maskedOutput:
        primary = primary_entity(detection)
        updates.update(
            {
                "risk": title_case_risk(detection.overall_risk.value),
                "riskScore": int(round(detection.risk_score * 100)),
                "finding": entity_label(primary.entity_type),
                "category": primary.category.value,
                "policyRule": "Audit write boundary sanitization enforced",
            }
        )
        if event.status.lower() == "allowed":
            updates["status"] = "Sanitized"
            updates["action"] = "Sensitive audit output sanitized"
    return event.model_copy(update=updates)


def audit_event_from_row(row: sqlite3.Row) -> AuditEvent:
    return AuditEvent(
        id=row["id"],
        timestamp=row["timestamp"],
        actor=row["actor"],
        department=row["department"],
        service=row["service"],
        action=row["action"],
        status=row["status"],
        risk=row["risk"],
        riskScore=row["risk_score"],
        finding=row["finding"],
        category=row["category"],
        policyRule=row["policy_rule"],
        maskedOutput=row["masked_output"],
        promptHash=row["prompt_hash"],
        source=row["source"],
        remoteId=row["remote_id"],
    )


def audit_filters(
    risk: str | None,
    status: str | None,
    service: str | None,
    actor: str | None,
) -> tuple[str, list[object]]:
    clauses: list[str] = []
    params: list[object] = []
    risk = risk.strip() if risk else None
    status = status.strip() if status else None
    service = service.strip() if service else None
    actor = actor.strip() if actor else None
    if risk:
        clauses.append("lower(risk) = lower(?)")
        params.append(risk)
    if status:
        clauses.append("lower(status) = lower(?)")
        params.append(status)
    if service:
        clauses.append("lower(service) LIKE lower(?)")
        params.append(f"%{service}%")
    if actor:
        clauses.append("lower(actor) LIKE lower(?)")
        params.append(f"%{actor}%")
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    return where, params


def csv_cell(value: object) -> str:
    text = str(value or "")
    if text.startswith(("=", "+", "-", "@", "\t", "\r")):
        text = f"'{text}"
    escaped = text.replace('"', '""')
    return f'"{escaped}"'


def title_case_risk(risk: str) -> RiskLevel:
    normalized = risk.strip().lower()
    if normalized == "critical":
        return "Critical"
    if normalized == "high":
        return "High"
    if normalized == "medium":
        return "Medium"
    return "Low"


async def call_ollama(sanitized_prompt: str) -> tuple[str, bool]:
    system = (
        "You are the local Secure AI Prompt Gateway assistant. "
        "Answer only using the sanitized prompt. Never ask for or reconstruct redacted secrets."
    )
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                f"{OLLAMA_BASE_URL.rstrip('/')}/api/generate",
                json={
                    "model": OLLAMA_MODEL,
                    "prompt": sanitized_prompt,
                    "system": system,
                    "stream": False,
                    "options": {"temperature": 0.2},
                },
            )
            response.raise_for_status()
            body = response.json()
            text = str(body.get("response") or "").strip()
            return text or "The sanitized prompt was processed by the local Ollama model.", True
    except Exception:
        return (
            "Sensitive data was detected and a sanitized prompt was prepared. Ollama is not reachable, so no model response was generated.",
            False,
        )


def build_gateway_audit_event(
    payload: GatewayPromptIn,
    user: dict[str, str],
    detection: DetectionResponse,
    sanitized_prompt: str,
    forwarded: bool,
    model_available: bool,
) -> AuditEventIn:
    finding = "No sensitive data detected"
    category = "Clean"
    if detection.detected_entities:
        primary = primary_entity(detection)
        finding = entity_label(primary.entity_type)
        category = primary.category.value

    if not detection.contains_sensitive_data:
        action, status = "Prompt analyzed and allowed", "Allowed"
    elif forwarded and model_available:
        action, status = "Redacted and sent to local Ollama", "Sanitized"
    elif forwarded:
        action, status = "Redacted; Ollama unavailable", "Sanitized"
    else:
        action, status = "Redacted; forwarding disabled", "Sanitized"

    return AuditEventIn(
        actor=user["email"],
        department=payload.department,
        service=payload.service,
        action=action,
        status=status,
        risk=title_case_risk(detection.overall_risk.value),
        riskScore=int(round(detection.risk_score * 100)),
        finding=finding,
        category=category,
        policyRule="Component 01 detection enforced; Component 02 and 03 extension points prepared",
        maskedOutput=sanitized_prompt,
        promptHash=hashlib.sha256(payload.prompt.encode("utf-8")).hexdigest(),
        source=payload.source,
    )


async def write_remote(event: AuditEventIn) -> str | None:
    if not REMOTE_AUDIT_API_URL:
        return None
    headers = {}
    if REMOTE_AUDIT_BEARER_TOKEN:
        headers["authorization"] = f"Bearer {REMOTE_AUDIT_BEARER_TOKEN}"

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(
                REMOTE_AUDIT_API_URL,
                json=event.model_dump(exclude={"originalPrompt"}),
                headers=headers,
            )
            response.raise_for_status()
            return response.json().get("id")
    except (httpx.HTTPError, ValueError) as exc:
        # The local SQLite record is authoritative; a SIEM outage must not
        # turn into a failed prompt or a lost audit event.
        LOGGER.warning("remote audit forwarding failed: %s", type(exc).__name__)
        return None


def write_local(event: AuditEventIn, remote_id: str | None) -> AuditEvent:
    event = harden_audit_event(event)
    audit = AuditEvent(
        id=f"AUD-{uuid4().hex[:10].upper()}",
        timestamp=datetime.now(timezone.utc).isoformat(),
        remoteId=remote_id,
        **event.model_dump(),
    )
    with connect() as connection:
        connection.execute(
            """
            INSERT INTO audit_events
            (id, timestamp, actor, department, service, action, status, risk, risk_score,
             finding, category, policy_rule, masked_output, prompt_hash, source, remote_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                audit.id,
                audit.timestamp,
                audit.actor,
                audit.department,
                audit.service,
                audit.action,
                audit.status,
                audit.risk,
                audit.riskScore,
                audit.finding,
                audit.category,
                audit.policyRule,
                audit.maskedOutput,
                audit.promptHash or "",
                audit.source,
                remote_id,
            ),
        )
    return audit


@app.get("/health")
def health() -> dict[str, object]:
    engine = get_detection_engine()
    detection = health_payload(engine)
    return {
        "status": "healthy",
        "service": "python-prompt-gateway",
        "detectionEngine": detection,
        "remoteAuditApiUrl": REMOTE_AUDIT_API_URL,
        "remoteAuthConfigured": bool(REMOTE_AUDIT_BEARER_TOKEN),
        "database": DB_PATH.name,
        "time": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/ready")
def ready() -> dict[str, object]:
    return root_ready(get_detection_engine())


@app.get("/metrics")
def metrics() -> Response:
    return root_metrics()


@app.get("/policies")
def policies(authorization: str | None = Header(default=None)) -> dict[str, object]:
    get_auth_user(authorization)
    return {
        "policies": [
            {"name": "Block credentials and tokens", "mode": "Enforce", "owner": "Security", "enabled": True},
            {"name": "Mask PCI data before AI submission", "mode": "Enforce", "owner": "Compliance", "enabled": True},
            {"name": "Mask PII before AI submission", "mode": "Enforce", "owner": "Privacy", "enabled": True},
            {"name": "Warn on source code or internal URLs", "mode": "Monitor", "owner": "Engineering", "enabled": True},
            {"name": "Default prompt leakage policy", "mode": "Monitor", "owner": "Security", "enabled": True},
        ]
    }


@app.get("/integrations")
async def integrations(authorization: str | None = Header(default=None)) -> dict[str, object]:
    get_auth_user(authorization)
    ollama_status = await ollama_model_status()
    engine = get_detection_engine()
    return {
        "integrations": [
            {"name": f"Ollama ({OLLAMA_MODEL})", "status": ollama_status, "mode": f"Local model at {OLLAMA_BASE_URL}"},
            {
                "name": "Detection Engine NER",
                "status": "Loaded" if engine.ner_available else "Regex only",
                "mode": "spaCy named-entity recognition",
            },
            {
                "name": "Remote Audit / SIEM",
                "status": "Configured" if REMOTE_AUDIT_API_URL else "Not configured",
                "mode": "Forwards masked audit events",
            },
            {"name": "SQLite Audit Store", "status": "Active", "mode": DB_PATH.name},
        ]
    }


async def ollama_model_status() -> str:
    try:
        async with httpx.AsyncClient(timeout=2) as client:
            response = await client.get(f"{OLLAMA_BASE_URL.rstrip('/')}/api/tags")
            response.raise_for_status()
            models = {str(model.get("name", "")) for model in response.json().get("models", [])}
    except (httpx.HTTPError, ValueError):
        return "Offline"
    return "Online" if OLLAMA_MODEL in models else "Model not pulled"


@app.post("/auth/register", response_model=AuthOut, status_code=201)
def register(payload: RegisterIn) -> AuthOut:
    init_db()
    email = payload.email.strip().lower()
    name = payload.name.strip()
    if not email or not name:
        raise HTTPException(status_code=400, detail="name and email are required")
    validate_password_strength(payload.password)

    with connect() as connection:
        count = connection.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"]
        role: Role = "admin" if count == 0 else "user"
        try:
            connection.execute(
                """
                INSERT INTO users (id, name, email, password_hash, role, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    f"USR-{uuid4().hex[:10].upper()}",
                    name,
                    email,
                    password_hash(payload.password),
                    role,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=409, detail="email is already registered") from exc
        row = connection.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    return auth_response(row)


@app.post("/admin/users", response_model=AuthOut, status_code=201)
def create_user(payload: CreateUserIn, authorization: str | None = Header(default=None)) -> AuthOut:
    current_user = get_auth_user(authorization)
    require_role(current_user, {"admin"})
    init_db()
    email = payload.email.strip().lower()
    name = payload.name.strip()
    if not email or not name:
        raise HTTPException(status_code=400, detail="name and email are required")
    validate_password_strength(payload.password)

    with connect() as connection:
        try:
            connection.execute(
                """
                INSERT INTO users (id, name, email, password_hash, role, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    f"USR-{uuid4().hex[:10].upper()}",
                    name,
                    email,
                    password_hash(payload.password),
                    payload.role,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=409, detail="email is already registered") from exc
        row = connection.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    return auth_response(row)


@app.delete("/admin/users/{user_id}")
def delete_user(user_id: str, authorization: str | None = Header(default=None)) -> dict[str, str]:
    current_user = get_auth_user(authorization)
    require_role(current_user, {"admin"})
    init_db()

    with connect() as connection:
        row = connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="user not found")
        if row["email"] == current_user["email"]:
            raise HTTPException(status_code=400, detail="you cannot delete your own account")
        connection.execute("DELETE FROM users WHERE id = ?", (user_id,))

    return {"status": "deleted", "id": user_id}


@app.post("/auth/login", response_model=AuthOut)
def login(payload: LoginIn, request: Request) -> AuthOut:
    init_db()
    email = payload.email.strip().lower()
    throttle_key = enforce_login_throttle(email, request)
    with connect() as connection:
        row = connection.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,),
        ).fetchone()
    if not row or not check_password(payload.password, row["password_hash"]):
        record_failed_login(throttle_key)
        raise HTTPException(status_code=401, detail="Invalid email or password")
    clear_failed_logins(throttle_key)
    return auth_response(row)


@app.get("/auth/me")
def me(authorization: str | None = Header(default=None)) -> dict[str, str]:
    return get_auth_user(authorization)


@app.get("/users")
def users(authorization: str | None = Header(default=None)) -> dict[str, object]:
    current_user = get_auth_user(authorization)
    require_role(current_user, {"admin"})
    init_db()
    with connect() as connection:
        rows = connection.execute(
            """
            SELECT u.id, u.name, u.email, u.role, u.created_at AS createdAt,
                   COUNT(a.id) AS promptCount,
                   SUM(CASE WHEN a.status = 'Blocked' THEN 1 ELSE 0 END) AS blockedCount
            FROM users u
            LEFT JOIN audit_events a ON a.actor = u.email
            GROUP BY u.id, u.name, u.email, u.role, u.created_at
            ORDER BY u.created_at DESC
            """
        ).fetchall()
    return {"users": [dict(row) for row in rows]}


@app.post("/inspect", response_model=AuditEvent)
async def inspect_and_log(
    payload: PromptInspectionIn,
    authorization: str | None = Header(default=None),
) -> AuditEvent:
    init_db()
    current_user = get_auth_user(authorization)
    require_role(current_user, {"admin"})
    try:
        event = inspect_prompt(payload, current_user["email"])
    except DetectionError as exc:
        raise HTTPException(status_code=400, detail={"code": exc.code, "message": exc.message}) from exc
    remote_id = await write_remote(event)
    return write_local(event, remote_id)


@app.post("/gateway/chat", response_model=GatewayPromptOut)
async def gateway_chat(
    payload: GatewayPromptIn,
    authorization: str | None = Header(default=None),
) -> GatewayPromptOut:
    init_db()
    current_user = get_auth_user(authorization)
    require_role(current_user, {"admin", "user"})

    engine = get_detection_engine()
    try:
        detection = engine.detect(DetectRequest(prompt=payload.prompt))
    except DetectionError as exc:
        raise HTTPException(status_code=400, detail={"code": exc.code, "message": exc.message}) from exc
    sanitized_prompt = redact_from_detection(payload.prompt, detection)

    should_forward = payload.forward_to_ollama
    assistant_message, ollama_available = await call_ollama(sanitized_prompt) if should_forward else (
        "Sensitive data was analyzed. Forwarding is disabled for this request.",
        False,
    )
    audit_event = write_local(
        build_gateway_audit_event(payload, current_user, detection, sanitized_prompt, should_forward, ollama_available),
        None,
    )

    if detection.contains_sensitive_data and ollama_available:
        action = "Detected sensitive data -> redacted -> sent to local Ollama safely."
        decision = "Redacted & Sent Safely"
    elif detection.contains_sensitive_data:
        action = "Detected sensitive data -> redacted -> Ollama unavailable."
        decision = "Redacted; Not Forwarded"
    else:
        action = "No sensitive data detected -> sent to local Ollama."
        decision = "Allowed"

    return GatewayPromptOut(
        requestId=detection.request_id,
        userPrompt=payload.prompt,
        sanitizedPrompt=sanitized_prompt,
        assistantMessage=assistant_message,
        policyDecision=decision,
        actionTaken=action,
        riskLevel=detection.overall_risk.value,
        riskScore=detection.risk_score,
        containsSensitiveData=detection.contains_sensitive_data,
        detectedEntities=[
            GatewayEntityOut(
                entityType=entity.entity_type,
                category=entity.category.value,
                maskedValue=entity.masked_value,
                riskLevel=entity.risk_level.value,
                confidence=entity.confidence,
                start=entity.start,
                end=entity.end,
            )
            for entity in detection.detected_entities
        ],
        auditEvents=[audit_event.model_dump(exclude={"originalPrompt"})],
        ollamaModel=OLLAMA_MODEL,
        ollamaAvailable=ollama_available,
        componentExtensionPoints={
            "component_02": "Prompt Sanitization & Risk Assessment can replace the current deterministic masking stage.",
            "component_03": "Security Policy & Access Control can replace the current allow/redact/forward decision stage.",
        },
        componentPlaceholders={
            "component_02": "Prompt Sanitization & Risk Assessment extension point prepared.",
            "component_03": "Security Policy & Access Control extension point prepared.",
        },
    )


@app.post("/audit/events", response_model=AuditEvent, status_code=201)
async def create_audit_event(
    payload: AuditEventIn,
    authorization: str | None = Header(default=None),
) -> AuditEvent:
    init_db()
    current_user = get_auth_user(authorization)
    require_role(current_user, {"admin"})
    remote_id = await write_remote(payload)
    return write_local(payload, remote_id)


@app.get("/audit/events", response_model=list[AuditEvent])
def list_audit_events(
    authorization: str | None = Header(default=None),
    risk: str | None = Query(default=None),
    status: str | None = Query(default=None),
    service: str | None = Query(default=None),
    actor: str | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=1000),
) -> list[AuditEvent]:
    init_db()
    current_user = get_auth_user(authorization)
    require_role(current_user, {"admin", "auditor"})
    where, params = audit_filters(risk, status, service, actor)
    with connect() as connection:
        rows = connection.execute(
            f"SELECT * FROM audit_events {where} ORDER BY timestamp DESC LIMIT ?",
            [*params, limit],
        ).fetchall()

    return [audit_event_from_row(row) for row in rows]


@app.get("/audit")
def audit_summary(
    authorization: str | None = Header(default=None),
    risk: str | None = Query(default=None),
    status: str | None = Query(default=None),
    service: str | None = Query(default=None),
    actor: str | None = Query(default=None),
) -> dict[str, object]:
    init_db()
    get_auth_user(authorization)
    where, params = audit_filters(risk, status, service, actor)
    with connect() as connection:
        events = connection.execute(f"SELECT * FROM audit_events {where} ORDER BY timestamp DESC LIMIT 100", params).fetchall()
        categories = connection.execute(f"SELECT category AS name, COUNT(*) AS value FROM audit_events {where} GROUP BY category ORDER BY value DESC", params).fetchall()
        risks = connection.execute(f"SELECT risk AS name, COUNT(*) AS value FROM audit_events {where} GROUP BY risk ORDER BY value DESC", params).fetchall()
        services = connection.execute(f"SELECT service AS name, COUNT(*) AS value FROM audit_events {where} GROUP BY service ORDER BY value DESC", params).fetchall()
        top_users = connection.execute(
            f"""
            SELECT actor AS name, department, SUM(CASE WHEN status = 'Blocked' THEN 1 ELSE 0 END) AS blocked
            FROM audit_events
            {where}
            GROUP BY actor, department
            ORDER BY blocked DESC, name ASC
            LIMIT 8
            """,
            params,
        ).fetchall()
        data_types = connection.execute(f"SELECT finding AS name, COUNT(*) AS value FROM audit_events {where} GROUP BY finding ORDER BY value DESC LIMIT 10", params).fetchall()
        totals = connection.execute(
            f"""
            SELECT
              COUNT(*) AS total,
              SUM(CASE WHEN status = 'Blocked' THEN 1 ELSE 0 END) AS blocked,
              SUM(CASE WHEN risk IN ('High', 'Critical') THEN 1 ELSE 0 END) AS highRisk,
              SUM(CASE WHEN category != 'Clean' THEN 1 ELSE 0 END) AS sensitive,
              COUNT(DISTINCT actor) AS activeUsers,
              AVG(risk_score) AS averageRiskScore
            FROM audit_events
            {where}
            """,
            params,
        ).fetchone()

    def rows(items: list[sqlite3.Row]) -> list[dict[str, object]]:
        return [dict(item) for item in items]

    return {
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "totals": dict(totals),
        "categories": rows(categories),
        "risks": rows(risks),
        "services": rows(services),
        "topUsers": rows(top_users),
        "recentEvents": [
            {
                "id": row["id"],
                "timestamp": row["timestamp"],
                "actor": row["actor"],
                "department": row["department"],
                "service": row["service"],
                "action": row["action"],
                "status": row["status"],
                "risk": row["risk"],
                "riskScore": row["risk_score"],
                "finding": row["finding"],
                "category": row["category"],
                "policyRule": row["policy_rule"],
                "maskedOutput": row["masked_output"],
                "source": row["source"],
            }
            for row in events
        ],
        "recentAlerts": [
            {
                "id": row["id"],
                "timestamp": row["timestamp"],
                "actor": row["actor"],
                "service": row["service"],
                "finding": row["finding"],
                "risk": row["risk"],
                "status": row["status"],
            }
            for row in events
            if row["risk"] in ("High", "Critical") or row["status"] == "Blocked"
        ][:10],
        "dataTypes": rows(data_types),
        "filters": {"risk": risk, "status": status, "service": service, "actor": actor},
        "componentHealth": {
            "component_01": "Sensitive Data Detection Engine active",
            "component_04": "Audit Logging and Security Dashboard active",
            "component_02": "Extension point prepared for Prompt Sanitization & Risk Assessment",
            "component_03": "Extension point prepared for Security Policy & Access Control",
        },
        "trend": [],
    }


@app.get("/reports/export")
def export_report(
    authorization: str | None = Header(default=None),
    risk: str | None = Query(default=None),
    status: str | None = Query(default=None),
    service: str | None = Query(default=None),
    actor: str | None = Query(default=None),
) -> Response:
    current_user = get_auth_user(authorization)
    require_role(current_user, {"admin", "auditor"})
    init_db()
    where, params = audit_filters(risk, status, service, actor)
    with connect() as connection:
        rows = connection.execute(
            f"""
            SELECT id, timestamp, actor, department, service, action, status, risk,
                   risk_score, finding, category, policy_rule, masked_output, source
            FROM audit_events
            {where}
            ORDER BY timestamp DESC
            """,
            params,
        ).fetchall()

    headers = [
        "id",
        "timestamp",
        "actor",
        "department",
        "service",
        "action",
        "status",
        "risk",
        "risk_score",
        "finding",
        "category",
        "policy_rule",
        "masked_output",
        "source",
    ]
    lines = [",".join(headers)]
    for row in rows:
        values = []
        for header in headers:
            values.append(csv_cell(row[header]))
        lines.append(",".join(values))

    return Response(
        "\n".join(lines),
        media_type="text/csv",
        headers={"content-disposition": "attachment; filename=secure-ai-audit-report.csv"},
    )


@app.post("/audit", response_model=AuditEvent, status_code=201)
async def create_audit_event_short(
    payload: AuditEventIn,
    authorization: str | None = Header(default=None),
) -> AuditEvent:
    return await create_audit_event(payload, authorization)
