from __future__ import annotations

import hashlib
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from uuid import uuid4

import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


RiskLevel = Literal["Low", "Medium", "High", "Critical"]

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "audit_logs.sqlite3"
REMOTE_AUDIT_API_URL = os.getenv(
    "REMOTE_AUDIT_API_URL",
    "https://secure-ai-prompt-gateway.rio6ix.chatgpt.site/api/audit",
)

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
    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.post(REMOTE_AUDIT_API_URL, json=event.model_dump())
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
        "database": DB_PATH.name,
        "time": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/inspect", response_model=AuditEvent)
async def inspect_and_log(payload: PromptInspectionIn) -> AuditEvent:
    init_db()
    event = inspect_prompt(payload)
    remote_id = await write_remote(event)
    return write_local(event, remote_id)


@app.post("/audit/events", response_model=AuditEvent, status_code=201)
async def create_audit_event(payload: AuditEventIn) -> AuditEvent:
    init_db()
    remote_id = await write_remote(payload)
    return write_local(payload, remote_id)


@app.get("/audit/events", response_model=list[AuditEvent])
def list_audit_events() -> list[AuditEvent]:
    init_db()
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
