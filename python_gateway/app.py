from __future__ import annotations

import hashlib
import base64
import hmac
import json
import os
import re
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from uuid import uuid4

import httpx
from fastapi import FastAPI, Header, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


RiskLevel = Literal["Low", "Medium", "High", "Critical"]
Role = Literal["admin", "auditor", "user"]

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "audit_logs.sqlite3"
REMOTE_AUDIT_API_URL = os.getenv(
    "REMOTE_AUDIT_API_URL",
    "",
)
REMOTE_AUDIT_BEARER_TOKEN = os.getenv("REMOTE_AUDIT_BEARER_TOKEN", "")
JWT_SECRET = os.getenv("JWT_SECRET", "local-dev-change-this-secret")

app = FastAPI(
    title="Secure AI Prompt Gateway Python Service",
    version="0.2.0",
    description="Python gateway service that masks sensitive prompt data and writes real audit events.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


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
    actor: str = Field(..., examples=["john.doe@company.com"])
    department: str = "Unknown"
    service: str = Field(..., examples=["ChatGPT Enterprise"])
    prompt: str
    source: str = "python-gateway"


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
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120_000).hex()
    return f"{salt}${digest}"


def check_password(password: str, stored: str) -> bool:
    salt, digest = stored.split("$", 1)
    return hmac.compare_digest(password_hash(password, salt), f"{salt}${digest}")


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


DETECTORS: list[tuple[str, str, re.Pattern[str], str]] = [
    ("Credentials & Secrets", "OpenAI/API Key", re.compile(r"\b(sk-(?:proj-)?[A-Za-z0-9_-]{16,})\b"), "Block credentials and tokens"),
    ("Credentials & Secrets", "AWS Access Key", re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), "Block credentials and tokens"),
    ("Credentials & Secrets", "Password", re.compile(r"(?i)\b(password|pwd)\s*[:=]\s*([^\s,;]{6,})"), "Block credentials and tokens"),
    ("Financial (PCI)", "Credit Card Number", re.compile(r"\b(?:\d[ -]*?){13,19}\b"), "Mask PCI data before AI submission"),
    ("PII", "Email Address", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "Mask PII before AI submission"),
    ("PII", "Phone Number", re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b"), "Mask PII before AI submission"),
    ("Source Code / IP", "Private Source Code", re.compile(r"(?s)\b(function|class|def|const|let|var)\b.{20,}"), "Warn on source code or internal URLs"),
]


def connect() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
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
        "exp": int(time.time()) + 60 * 60 * 12,
    })
    return AuthOut(token=token, user=user)


def mask_value(match: re.Match[str]) -> str:
    value = match.group(0)
    if len(value) <= 8:
      return "****"
    return f"{value[:4]}{'*' * max(4, len(value) - 8)}{value[-4:]}"


def inspect_prompt(payload: PromptInspectionIn) -> AuditEventIn:
    masked = payload.prompt
    matches: list[tuple[str, str, str]] = []

    for category, finding, pattern, policy in DETECTORS:
        if pattern.search(masked):
            masked = pattern.sub(mask_value, masked)
            matches.append((category, finding, policy))

    if not matches:
        category, finding, policy = "Clean", "No sensitive data detected", "Default prompt leakage policy"
        risk: RiskLevel = "Low"
        status = "Allowed"
        action = "Prompt allowed"
        score = 8
    else:
        category, finding, policy = matches[0]
        secret_hit = category == "Credentials & Secrets"
        risk = "High" if secret_hit else "Medium"
        status = "Blocked" if secret_hit else "Sanitized"
        action = "Prompt blocked" if secret_hit else "Prompt sanitized"
        score = 92 if secret_hit else 58

    return AuditEventIn(
        actor=payload.actor,
        department=payload.department,
        service=payload.service,
        action=action,
        status=status,
        risk=risk,
        riskScore=score,
        finding=finding,
        category=category,
        policyRule=policy,
        maskedOutput=masked,
        originalPrompt=payload.prompt,
        promptHash=hashlib.sha256(payload.prompt.encode("utf-8")).hexdigest(),
        source=payload.source,
    )


async def write_remote(event: AuditEventIn) -> str | None:
    if not REMOTE_AUDIT_API_URL:
        return None
    headers = {}
    if REMOTE_AUDIT_BEARER_TOKEN:
        headers["authorization"] = f"Bearer {REMOTE_AUDIT_BEARER_TOKEN}"

    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.post(
            REMOTE_AUDIT_API_URL,
            json=event.model_dump(),
            headers=headers,
        )
        response.raise_for_status()
        body = response.json()
        return body.get("id")


def write_local(event: AuditEventIn, remote_id: str | None) -> AuditEvent:
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


@app.on_event("startup")
def on_startup() -> None:
    init_db()


@app.get("/health")
def health() -> dict[str, object]:
    return {
        "status": "healthy",
        "service": "python-prompt-gateway",
        "remoteAuditApiUrl": REMOTE_AUDIT_API_URL,
        "remoteAuthConfigured": bool(REMOTE_AUDIT_BEARER_TOKEN),
        "database": DB_PATH.name,
        "time": datetime.now(timezone.utc).isoformat(),
    }


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
def integrations(authorization: str | None = Header(default=None)) -> dict[str, object]:
    get_auth_user(authorization)
    return {
        "integrations": [
            {"name": "ChatGPT Enterprise", "status": "Ready", "mode": "Prompt gateway"},
            {"name": "Google Gemini", "status": "Ready", "mode": "Prompt gateway"},
            {"name": "Microsoft Copilot", "status": "Ready", "mode": "Prompt gateway"},
            {"name": "Browser Extension", "status": "Local backend", "mode": "JavaScript extension"},
        ]
    }


@app.post("/auth/register", response_model=AuthOut, status_code=201)
def register(payload: RegisterIn) -> AuthOut:
    init_db()
    email = payload.email.strip().lower()
    name = payload.name.strip()
    if not email or not name:
        raise HTTPException(status_code=400, detail="name and email are required")

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


@app.post("/auth/login", response_model=AuthOut)
def login(payload: LoginIn) -> AuthOut:
    init_db()
    with connect() as connection:
        row = connection.execute(
            "SELECT * FROM users WHERE email = ?",
            (payload.email.strip().lower(),),
        ).fetchone()
    if not row or not check_password(payload.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
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
    event = inspect_prompt(payload)
    remote_id = await write_remote(event)
    return write_local(event, remote_id)


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
def list_audit_events(authorization: str | None = Header(default=None)) -> list[AuditEvent]:
    init_db()
    current_user = get_auth_user(authorization)
    require_role(current_user, {"admin", "auditor"})
    with connect() as connection:
        rows = connection.execute(
            "SELECT * FROM audit_events ORDER BY timestamp DESC LIMIT 200"
        ).fetchall()

    return [
        AuditEvent(
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
        for row in rows
    ]


@app.get("/audit")
def audit_summary(authorization: str | None = Header(default=None)) -> dict[str, object]:
    init_db()
    get_auth_user(authorization)
    with connect() as connection:
        events = connection.execute("SELECT * FROM audit_events ORDER BY timestamp DESC LIMIT 100").fetchall()
        categories = connection.execute("SELECT category AS name, COUNT(*) AS value FROM audit_events GROUP BY category ORDER BY value DESC").fetchall()
        risks = connection.execute("SELECT risk AS name, COUNT(*) AS value FROM audit_events GROUP BY risk ORDER BY value DESC").fetchall()
        services = connection.execute("SELECT service AS name, COUNT(*) AS value FROM audit_events GROUP BY service ORDER BY value DESC").fetchall()
        top_users = connection.execute(
            """
            SELECT actor AS name, department, SUM(CASE WHEN status = 'Blocked' THEN 1 ELSE 0 END) AS blocked
            FROM audit_events
            GROUP BY actor, department
            ORDER BY blocked DESC, name ASC
            LIMIT 8
            """
        ).fetchall()
        data_types = connection.execute("SELECT finding AS name, COUNT(*) AS value FROM audit_events GROUP BY finding ORDER BY value DESC LIMIT 10").fetchall()
        totals = connection.execute(
            """
            SELECT
              COUNT(*) AS total,
              SUM(CASE WHEN status = 'Blocked' THEN 1 ELSE 0 END) AS blocked,
              SUM(CASE WHEN risk IN ('High', 'Critical') THEN 1 ELSE 0 END) AS highRisk,
              COUNT(DISTINCT actor) AS activeUsers,
              AVG(risk_score) AS averageRiskScore
            FROM audit_events
            """
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
        "trend": [],
    }


@app.get("/reports/export")
def export_report(authorization: str | None = Header(default=None)) -> Response:
    current_user = get_auth_user(authorization)
    require_role(current_user, {"admin", "auditor"})
    init_db()
    with connect() as connection:
        rows = connection.execute(
            """
            SELECT id, timestamp, actor, department, service, action, status, risk,
                   risk_score, finding, category, policy_rule, masked_output, source
            FROM audit_events
            ORDER BY timestamp DESC
            """
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
            value = str(row[header] or "").replace('"', '""')
            values.append(f'"{value}"')
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
