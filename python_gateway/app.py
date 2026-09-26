from __future__ import annotations

import hashlib
import hmac
import os
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from uuid import uuid4

import httpx
from fastapi import FastAPI, Header, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

try:
    from .security import SecurityService
except ImportError:
    from security import SecurityService


RiskLevel = Literal["Low", "Medium", "High", "Critical"]
Role = Literal["admin", "auditor", "user", "approver"]

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "audit_logs.sqlite3"
REMOTE_AUDIT_API_URL = os.getenv(
    "REMOTE_AUDIT_API_URL",
    "",
)
REMOTE_AUDIT_BEARER_TOKEN = os.getenv("REMOTE_AUDIT_BEARER_TOKEN", "")

app = FastAPI(
    title="Secure AI Prompt Gateway Python Service",
    version="0.2.0",
    description="Python gateway service that masks sensitive prompt data and writes real audit events.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000,http://localhost:5173,http://127.0.0.1:5173").split(","),
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["*"],
)


class RegisterIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=120, examples=["Security Admin"])
    email: str = Field(..., min_length=3, max_length=254, pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$", examples=["sec.admin@company.com"])
    password: str = Field(..., min_length=12, max_length=128)


class CreateUserIn(RegisterIn):
    role: Role = "user"


class LoginIn(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(max_length=128)


class AuthOut(BaseModel):
    token: str
    user: dict[str, str]


class PasswordChangeIn(BaseModel):
    current_password: str = Field(max_length=128)
    new_password: str = Field(min_length=12, max_length=128)


class PasswordResetIn(BaseModel):
    new_password: str = Field(min_length=12, max_length=128)


class PromptInspectionIn(BaseModel):
    actor: str = Field(..., examples=["john.doe@company.com"])
    department: str = "Unknown"
    service: str = Field(..., examples=["ChatGPT Enterprise"])
    prompt: str = Field(min_length=1, max_length=10000)
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


class InspectionResult(AuditEvent):
    decision: str
    send_allowed: bool
    policy_version: int
    approval_id: str | None = None


@app.exception_handler(RequestValidationError)
async def invalid_request(_request, _error):
    # Pydantic's default response may echo raw prompts or passwords in 'input'.
    return JSONResponse(status_code=422, content={"detail": "Invalid request fields or policy configuration"})


def password_hash(password: str, salt: str | None = None) -> str:
    salt = salt or uuid4().hex
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 600_000).hex()
    return f"600000${salt}${digest}"


def check_password(password: str, stored: str) -> bool:
    try:
        parts = stored.split("$")
        iterations, salt, digest = (120000, *parts) if len(parts) == 2 else (int(parts[0]), parts[1], parts[2])
        if not 120000 <= iterations <= 1000000:
            return False
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), iterations).hex()
        return hmac.compare_digest(candidate, digest)
    except (ValueError, IndexError):
        return False


def get_auth_user(authorization: str | None) -> dict[str, str]:
    return security.identity(authorization)


def normalize_role(role: str) -> Role:
    normalized = role.strip().lower().replace("security admin", "admin")
    if normalized in ("admin", "auditor", "user", "approver"):
        return normalized  # type: ignore[return-value]
    raise HTTPException(403, "Unsupported account role")


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


@contextmanager
def connect():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    try:
        with connection:
            yield connection
    finally:
        connection.close()


security = SecurityService(connect)
app.include_router(security.router())


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
        security.initialize(connection)
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
    token = security.issue(row["id"])
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
        if pattern.search(payload.prompt):
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
        originalPrompt=None,
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
            json=event.model_dump(exclude={"originalPrompt"}),
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
    policy = security.policy()
    return {"version": policy["version"], "policies": [dict(r, mode=r["action"], owner="Security") for r in policy["rules"]]}


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
        # Admin bootstrap is a local operator command, never public registration.
        role: Role = "user"
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


@app.post("/admin/users", status_code=201)
def create_user(payload: CreateUserIn, authorization: str | None = Header(default=None)) -> dict:
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
        security.change(connection, current_user["email"], "USER_CREATED", row["id"], {"role": payload.role})
    return {"user": {"id": row["id"], "name": row["name"], "email": row["email"], "role": row["role"]}}


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
        connection.execute("DELETE FROM security_sessions WHERE user_id=?", (user_id,))
        security.change(connection, current_user["email"], "USER_DELETED", user_id, {})

    return {"status": "deleted", "id": user_id}


@app.post("/auth/login", response_model=AuthOut)
def login(payload: LoginIn) -> AuthOut:
    init_db()
    email = payload.email.strip().lower()
    security.login_check(email)
    with connect() as connection:
        row = connection.execute(
            "SELECT * FROM users WHERE email = ?",
            (payload.email.strip().lower(),),
        ).fetchone()
    valid = check_password(payload.password, row["password_hash"]) if row else check_password(payload.password, "600000$"+"0"*32+"$"+"0"*64)
    valid = bool(valid and row and row["active"])
    security.login_result(email, valid)
    if not valid:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if row["password_hash"].count("$") == 1:
        with connect() as connection:
            connection.execute("UPDATE users SET password_hash=? WHERE id=?", (password_hash(payload.password), row["id"]))
    return auth_response(row)


@app.post("/auth/password")
def change_password(payload: PasswordChangeIn, authorization: str | None = Header(default=None)):
    user = get_auth_user(authorization)
    security.login_check(user["email"])
    with connect() as connection:
        row = connection.execute("SELECT password_hash FROM users WHERE id=?", (user["id"],)).fetchone()
    valid = bool(row and check_password(payload.current_password, row[0]))
    security.login_result(user["email"], valid)
    if not valid:
        raise HTTPException(400, "Current password is incorrect")
    with connect() as connection:
        connection.execute("UPDATE users SET password_hash=? WHERE id=?", (password_hash(payload.new_password), user["id"]))
        connection.execute("DELETE FROM security_sessions WHERE user_id=?", (user["id"],))
        security.change(connection, user["email"], "PASSWORD_CHANGED", user["id"], {})
    return {"status": "changed", "message": "Sign in again"}


@app.post("/admin/users/{user_id}/password")
def reset_password(user_id: str, payload: PasswordResetIn, authorization: str | None = Header(default=None)):
    user = security.require(authorization, {"admin"})
    if user_id == user["id"]:
        raise HTTPException(400, "Use your own password-change form")
    with connect() as connection:
        cursor = connection.execute("UPDATE users SET password_hash=? WHERE id=?", (password_hash(payload.new_password), user_id))
        if cursor.rowcount != 1:
            raise HTTPException(404, "User not found")
        connection.execute("DELETE FROM security_sessions WHERE user_id=?", (user_id,))
        security.change(connection, user["email"], "PASSWORD_RESET", user_id, {})
    return {"status": "reset"}


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
            SELECT u.id, u.name, u.email, u.role, u.active, u.created_at AS createdAt,
                   COUNT(a.id) AS promptCount,
                   SUM(CASE WHEN a.status = 'Blocked' THEN 1 ELSE 0 END) AS blockedCount
            FROM users u
            LEFT JOIN audit_events a ON a.actor = u.email
            GROUP BY u.id, u.name, u.email, u.role, u.created_at
            ORDER BY u.created_at DESC
            """
        ).fetchall()
    return {"users": [dict(row) for row in rows]}


@app.post("/inspect", response_model=InspectionResult)
async def inspect_and_log(
    payload: PromptInspectionIn,
    authorization: str | None = Header(default=None),
) -> InspectionResult:
    init_db()
    current_user = get_auth_user(authorization)
    security.precheck(current_user, payload.service)
    payload = payload.model_copy(update={"actor": current_user["email"]})
    event = inspect_prompt(payload)
    categories = sorted({category for category, _, pattern, _ in DETECTORS if pattern.search(payload.prompt)})
    decision, reason, version = security.evaluate(current_user, payload.service, categories, event.riskScore)
    # Consume only the existing detector's spans; masking remains Component 2's job.
    # Full replacement is required for the policy-controlled outbound preview.
    safe = payload.prompt
    spans = sorted((m.start(), m.end()) for _, _, pattern, _ in DETECTORS for m in pattern.finditer(payload.prompt))
    merged = []
    for start, end in spans:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    for start, end in reversed(merged):
        safe = safe[:start] + "[REDACTED]" + safe[end:]
    approval_id = security.request_approval(current_user, payload.service, safe, version) if decision == "REQUIRE_APPROVAL" else None
    event = event.model_copy(update={"policyRule": reason, "maskedOutput": "" if decision == "BLOCK" else safe,
                                    "status": {"ALLOW": "Allowed", "SANITIZE": "Sanitized", "BLOCK": "Blocked", "REQUIRE_APPROVAL": "Pending approval"}[decision],
                                    "action": decision})
    remote_id = await write_remote(event)
    audit = write_local(event, remote_id)
    return InspectionResult(**audit.model_dump(), decision=decision, send_allowed=decision in {"ALLOW", "SANITIZE"}, policy_version=version, approval_id=approval_id)


@app.post("/audit/events", response_model=AuditEvent, status_code=201)
async def create_audit_event(
    payload: AuditEventIn,
    authorization: str | None = Header(default=None),
) -> AuditEvent:
    init_db()
    current_user = get_auth_user(authorization)
    require_role(current_user, {"admin"})
    payload = payload.model_copy(update={"originalPrompt": None, "actor": current_user["email"]})
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
    current_user = get_auth_user(authorization)
    require_role(current_user, {"admin", "auditor"})
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
