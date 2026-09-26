"""Component 3: server-side sessions, policy decisions and approval lifecycle.

This module does not detect or score prompt content. The gateway supplies findings.
"""

import hashlib
import json
import secrets
import time
from typing import Literal

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field, model_validator

Role = Literal["admin", "auditor", "user", "approver"]
Action = Literal["ALLOW", "SANITIZE", "BLOCK", "REQUIRE_APPROVAL"]
CATEGORIES = {"Clean", "PII", "Financial (PCI)", "Credentials & Secrets", "Source Code / IP"}
SERVICES = {"ChatGPT Enterprise", "Google Gemini", "Microsoft Copilot"}
DEFAULT_RULES = [
    dict(id="credentials", name="Block credentials and tokens", category="Credentials & Secrets", action="BLOCK"),
    dict(id="financial", name="Mask PCI data before AI submission", category="Financial (PCI)", action="SANITIZE"),
    dict(id="pii", name="Mask PII before AI submission", category="PII", action="SANITIZE"),
    dict(id="source-code", name="Review source code", category="Source Code / IP", action="REQUIRE_APPROVAL"),
]


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^[a-z0-9-]{1,50}$")
    name: str = Field(min_length=1, max_length=120)
    category: str
    action: Action
    roles: list[Role] = Field(default_factory=lambda: ["admin", "user", "approver"], min_length=1)
    services: list[str] = Field(default_factory=lambda: sorted(SERVICES), min_length=1)
    min_score: int = Field(default=0, ge=0, le=100)
    max_score: int = Field(default=100, ge=0, le=100)
    enabled: bool = True

    @model_validator(mode="after")
    def validate_rule(self):
        if self.category not in CATEGORIES or not set(self.services) <= SERVICES:
            raise ValueError("Unsupported category or service")
        if self.min_score > self.max_score:
            raise ValueError("Minimum score exceeds maximum")
        if self.category != "Clean" and self.action == "ALLOW":
            raise ValueError("Sensitive categories cannot be allowed without sanitization")
        if self.category == "Credentials & Secrets" and self.action != "BLOCK":
            raise ValueError("Credentials must always be blocked")
        return self


class PolicyUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_version: int = Field(ge=1)
    rules: list[Rule] = Field(max_length=100)

    @model_validator(mode="after")
    def unique_ids(self):
        if len({r.id for r in self.rules}) != len(self.rules):
            raise ValueError("Rule IDs must be unique")
        return self


class UserUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: Role
    active: bool


class ApprovalDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: Literal["APPROVED", "REJECTED"]
    reason: str = Field(min_length=1, max_length=500)


class SecurityService:
    def __init__(self, connect):
        self.connect = connect

    def initialize(self, db):
        columns = {r[1] for r in db.execute("PRAGMA table_info(users)")}
        if "active" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN active INTEGER NOT NULL DEFAULT 1")
        db.executescript("""
            CREATE TABLE IF NOT EXISTS security_sessions (
                token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS security_login_attempts (
                identity TEXT PRIMARY KEY, failures INTEGER NOT NULL, reset_at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS security_policy (
                id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL, rules TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS security_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL,
                actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, details TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS security_approvals (
                id TEXT PRIMARY KEY, requester TEXT NOT NULL, service TEXT NOT NULL,
                sanitized_prompt TEXT NOT NULL, policy_version INTEGER NOT NULL,
                status TEXT NOT NULL, expires INTEGER NOT NULL, reviewer TEXT, reason TEXT);
        """)
        rules = [Rule(**r).model_dump() for r in DEFAULT_RULES]
        db.execute("INSERT OR IGNORE INTO security_policy VALUES (1,1,?)", (json.dumps(rules),))

    @staticmethod
    def change(db, actor, action, target, details):
        db.execute("INSERT INTO security_changes(timestamp,actor,action,target,details) VALUES (?,?,?,?,?)",
                   (int(time.time()), actor, action, target, json.dumps(details)))

    def issue(self, user_id):
        token = secrets.token_urlsafe(32)
        with self.connect() as db:
            db.execute("DELETE FROM security_sessions WHERE expires <= ?", (int(time.time()),))
            db.execute("INSERT INTO security_sessions VALUES (?,?,?)",
                       (hashlib.sha256(token.encode()).hexdigest(), user_id, int(time.time()) + 8 * 3600))
        return token

    def identity(self, authorization):
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(401, "Login required")
        token = authorization.split(" ", 1)[1]
        if not token or len(token) > 512:
            raise HTTPException(401, "Invalid or expired login")
        with self.connect() as db:
            row = db.execute("""SELECT u.id,u.name,u.email,u.role,u.active FROM users u
                JOIN security_sessions s ON s.user_id=u.id WHERE s.token_hash=? AND s.expires>?""",
                (hashlib.sha256(token.encode()).hexdigest(), int(time.time()))).fetchone()
        if not row or not row["active"] or row["role"] not in {"admin", "auditor", "user", "approver"}:
            raise HTTPException(401, "Invalid or expired login")
        return {key: row[key] for key in ("id", "name", "email", "role")}

    def require(self, authorization, roles):
        user = self.identity(authorization)
        if user["role"] not in roles:
            raise HTTPException(403, "You do not have permission for this action")
        return user

    def login_check(self, email):
        with self.connect() as db:
            row = db.execute("SELECT * FROM security_login_attempts WHERE identity=?", (email,)).fetchone()
        if row and row["reset_at"] > time.time() and row["failures"] >= 5:
            raise HTTPException(429, "Too many login attempts; try again in 15 minutes")

    def login_result(self, email, success):
        with self.connect() as db:
            if success:
                db.execute("DELETE FROM security_login_attempts WHERE identity=?", (email,))
            else:
                now = int(time.time())
                db.execute("DELETE FROM security_login_attempts WHERE reset_at<=?", (now,))
                db.execute("""INSERT INTO security_login_attempts VALUES (?,1,?)
                    ON CONFLICT(identity) DO UPDATE SET failures=failures+1""", (email, now+900))
            self.change(db, email, "LOGIN_SUCCESS" if success else "LOGIN_FAILURE", "session", {})

    def policy(self):
        with self.connect() as db:
            row = db.execute("SELECT version,rules FROM security_policy WHERE id=1").fetchone()
        return {"version": row["version"], "rules": json.loads(row["rules"])}

    def precheck(self, user, service):
        if user["role"] not in {"admin", "user", "approver"} or service not in SERVICES:
            with self.connect() as db:
                self.change(db, user["email"], "ACCESS_DENIED", "provider", {"service": service[:120]})
            raise HTTPException(403, "This role or provider is not authorized for prompt submission")

    def evaluate(self, user, service, categories, score):
        self.precheck(user, service)
        if not set(categories) <= CATEGORIES or isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 100:
            raise ValueError("Invalid trusted risk assessment")
        policy = self.policy()
        if "Credentials & Secrets" in categories or score >= 90:
            return "BLOCK", "Mandatory credential or critical-risk block", policy["version"]
        if not categories or set(categories) == {"Clean"}:
            return "ALLOW", "No sensitive findings", policy["version"]
        matches = [Rule(**r) for r in policy["rules"]]
        matches = [r for r in matches if r.enabled and r.category in categories
                   and user["role"] in r.roles and service in r.services and r.min_score <= score <= r.max_score]
        # Every detected category needs coverage. Missing/disabled rules cannot weaken protection.
        if not set(categories) <= {r.category for r in matches}:
            return "BLOCK", "No applicable policy for every detected category", policy["version"]
        priority = {"ALLOW": 0, "SANITIZE": 1, "REQUIRE_APPROVAL": 2, "BLOCK": 3}
        selected = max(matches, key=lambda r: (priority[r.action], r.id))
        return selected.action, selected.name, policy["version"]

    def request_approval(self, user, service, sanitized_prompt, version):
        approval_id = secrets.token_hex(16)
        with self.connect() as db:
            db.execute("INSERT INTO security_approvals VALUES (?,?,?,?,?,'PENDING',?,NULL,NULL)",
                       (approval_id, user["id"], service, sanitized_prompt, version, int(time.time())+3600))
            self.change(db, user["email"], "APPROVAL_REQUESTED", approval_id, {"policy_version": version})
        return approval_id

    def router(self):
        router = APIRouter()

        @router.post("/auth/logout")
        def logout(authorization: str | None = Header(default=None)):
            user = self.identity(authorization)
            with self.connect() as db:
                db.execute("DELETE FROM security_sessions WHERE token_hash=?",
                           (hashlib.sha256(authorization.split(" ", 1)[1].encode()).hexdigest(),))
                self.change(db, user["email"], "LOGOUT", "session", {})
            return {"status": "logged_out"}

        @router.get("/security/policy")
        def get_policy(authorization: str | None = Header(default=None)):
            self.identity(authorization)
            return self.policy()

        @router.put("/security/policy")
        def update_policy(payload: PolicyUpdate, authorization: str | None = Header(default=None)):
            user = self.require(authorization, {"admin"})
            rules = [r.model_dump() for r in payload.rules]
            with self.connect() as db:
                cursor = db.execute("UPDATE security_policy SET version=version+1,rules=? WHERE id=1 AND version=?",
                                    (json.dumps(rules), payload.expected_version))
                if cursor.rowcount != 1:
                    raise HTTPException(409, "Policy changed; reload before saving")
                self.change(db, user["email"], "POLICY_UPDATED", "policy", {"version": payload.expected_version+1, "rules": rules})
            return self.policy()

        @router.patch("/admin/users/{user_id}")
        def update_user(user_id: str, payload: UserUpdate, authorization: str | None = Header(default=None)):
            user = self.require(authorization, {"admin"})
            if user_id == user["id"]:
                raise HTTPException(400, "You cannot change your own role or active status")
            with self.connect() as db:
                cursor = db.execute("UPDATE users SET role=?,active=? WHERE id=?", (payload.role, int(payload.active), user_id))
                if cursor.rowcount != 1:
                    raise HTTPException(404, "User not found")
                db.execute("DELETE FROM security_sessions WHERE user_id=?", (user_id,))
                self.change(db, user["email"], "USER_UPDATED", user_id, payload.model_dump())
            return {"status": "updated"}

        @router.get("/security/changes")
        def changes(authorization: str | None = Header(default=None)):
            self.require(authorization, {"admin", "auditor"})
            with self.connect() as db:
                return [dict(r) for r in db.execute("SELECT * FROM security_changes ORDER BY id DESC LIMIT 200")]

        @router.get("/security/approvals")
        def approvals(authorization: str | None = Header(default=None)):
            user = self.identity(authorization)
            with self.connect() as db:
                db.execute("UPDATE security_approvals SET status='EXPIRED' WHERE status IN ('PENDING','APPROVED') AND expires<=?", (int(time.time()),))
                query = "SELECT * FROM security_approvals"
                args = ()
                if user["role"] not in {"admin", "approver", "auditor"}:
                    query += " WHERE requester=?"
                    args = (user["id"],)
                return [dict(r) for r in db.execute(query+" ORDER BY expires DESC LIMIT 100", args)]

        @router.post("/security/approvals/{approval_id}/decision")
        def decide(approval_id: str, payload: ApprovalDecision, authorization: str | None = Header(default=None)):
            user = self.require(authorization, {"admin", "approver"})
            with self.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute("SELECT * FROM security_approvals WHERE id=?", (approval_id,)).fetchone()
                if not row:
                    raise HTTPException(404, "Approval not found")
                if row["requester"] == user["id"]:
                    raise HTTPException(403, "You cannot approve your own request")
                if row["status"] != "PENDING" or row["expires"] <= time.time():
                    raise HTTPException(409, "Approval is no longer pending")
                if row["policy_version"] != db.execute("SELECT version FROM security_policy WHERE id=1").fetchone()[0]:
                    raise HTTPException(409, "Policy changed; submit the prompt again")
                db.execute("UPDATE security_approvals SET status=?,reviewer=?,reason=? WHERE id=?", (payload.decision, user["id"], payload.reason, approval_id))
                self.change(db, user["email"], payload.decision, approval_id, {"reason": payload.reason})
            return {"status": payload.decision}

        @router.post("/security/approvals/{approval_id}/consume")
        def consume(approval_id: str, authorization: str | None = Header(default=None)):
            user = self.identity(authorization)
            with self.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute("SELECT * FROM security_approvals WHERE id=? AND requester=?", (approval_id, user["id"])).fetchone()
                if not row:
                    raise HTTPException(404, "Approval not found")
                if user["role"] not in {"admin", "user", "approver"} or row["service"] not in SERVICES:
                    raise HTTPException(403, "Prompt submission is no longer authorized")
                version = db.execute("SELECT version FROM security_policy WHERE id=1").fetchone()[0]
                if row["status"] != "APPROVED" or row["expires"] <= time.time() or row["policy_version"] != version:
                    raise HTTPException(409, "Approval unavailable, expired, consumed, or policy changed")
                db.execute("UPDATE security_approvals SET status='CONSUMED',sanitized_prompt='' WHERE id=?", (approval_id,))
                self.change(db, user["email"], "APPROVAL_CONSUMED", approval_id, {})
            return {"decision": "SANITIZE", "send_allowed": True, "service": row["service"], "sanitized_prompt": row["sanitized_prompt"]}

        return router
