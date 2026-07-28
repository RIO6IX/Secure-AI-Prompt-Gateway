from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from uuid import uuid4

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


RiskLevel = Literal["Low", "Medium", "High", "Critical"]

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "audit_logs.sqlite3"

app = FastAPI(
    title="Secure AI Prompt Gateway Audit Service",
    version="0.1.0",
    description="Python audit logging API for prompt gateway decisions.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


class AuditEventIn(BaseModel):
    actor: str = Field(..., examples=["john.doe@company.com"])
    action: str = Field(..., examples=["Prompt blocked"])
    target: str = Field(..., examples=["ChatGPT Enterprise"])
    finding: str = Field(..., examples=["API key"])
    masked_output: str = Field(..., examples=["sk-proj-********************************"])
    risk: RiskLevel = "Medium"
    status: str = Field(..., examples=["Blocked"])


class AuditEvent(AuditEventIn):
    id: str
    timestamp: str


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
              action TEXT NOT NULL,
              target TEXT NOT NULL,
              finding TEXT NOT NULL,
              masked_output TEXT NOT NULL,
              risk TEXT NOT NULL,
              status TEXT NOT NULL
            )
            """
        )


@app.on_event("startup")
def on_startup() -> None:
    init_db()


@app.get("/health")
def health() -> dict[str, object]:
    return {
        "status": "healthy",
        "service": "audit-logging",
        "database": DB_PATH.name,
        "time": datetime.now(timezone.utc).isoformat(),
    }


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
            action=row["action"],
            target=row["target"],
            finding=row["finding"],
            masked_output=row["masked_output"],
            risk=row["risk"],
            status=row["status"],
        )
        for row in rows
    ]


@app.post("/audit/events", response_model=AuditEvent, status_code=201)
def create_audit_event(payload: AuditEventIn) -> AuditEvent:
    init_db()
    event = AuditEvent(
        id=f"AUD-{uuid4().hex[:8].upper()}",
        timestamp=datetime.now(timezone.utc).isoformat(),
        **payload.model_dump(),
    )

    with connect() as connection:
        connection.execute(
            """
            INSERT INTO audit_events
            (id, timestamp, actor, action, target, finding, masked_output, risk, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.id,
                event.timestamp,
                event.actor,
                event.action,
                event.target,
                event.finding,
                event.masked_output,
                event.risk,
                event.status,
            ),
        )

    return event

