"""HTTP security regression tests using an isolated temporary SQLite database."""
import hashlib
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from python_gateway import app as gateway


class Component3Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.password_digest = gateway.password_hash("FictionalPass123!")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.original = gateway.DB_PATH
        gateway.DB_PATH = Path(self.temp.name) / "test.sqlite3"
        self.remote = patch.object(gateway, "REMOTE_AUDIT_API_URL", "")
        self.remote.start()
        gateway.init_db()
        self.client = TestClient(gateway.app)
        self.accounts = {}
        for role in ("admin", "user", "auditor", "approver"):
            with gateway.connect() as db:
                db.execute("INSERT INTO users(id,name,email,password_hash,role,created_at) VALUES (?,?,?,?,?,'test')",
                           (role, role, role+"@example.test", self.password_digest, role))
            self.accounts[role] = {"Authorization": "Bearer " + gateway.security.issue(role)}

    def tearDown(self):
        self.client.close()
        gateway.DB_PATH = self.original
        self.remote.stop()
        self.temp.cleanup()

    def inspect(self, prompt="Explain least privilege", role="user", **extra):
        payload = dict(prompt=prompt, actor="spoofed@example.test", service="ChatGPT Enterprise")
        payload.update(extra)
        return self.client.post("/inspect", json=payload, headers=self.accounts[role])

    def policy(self):
        return self.client.get("/security/policy", headers=self.accounts["admin"]).json()

    def save(self, policy, role="admin"):
        return self.client.put("/security/policy", json={"expected_version": policy["version"], "rules": policy["rules"]}, headers=self.accounts[role])

    def pending(self):
        result = self.inspect("const internalCustomerRecords = confidentialRecords;").json()
        self.assertEqual(result["decision"], "REQUIRE_APPROVAL")
        self.assertFalse(result["send_allowed"])
        return result["approval_id"]

    def decide(self, identifier, role="approver", decision="APPROVED"):
        return self.client.post(f"/security/approvals/{identifier}/decision", json={"decision": decision, "reason": "Reviewed synthetic test"}, headers=self.accounts[role])

    def consume(self, identifier, role="user"):
        return self.client.post(f"/security/approvals/{identifier}/consume", headers=self.accounts[role])

    def test_all_protected_routes_require_authentication(self):
        for path in ("/auth/me", "/users", "/audit", "/audit/events", "/reports/export", "/security/policy", "/security/approvals", "/security/changes"):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 401)

    def test_clean_prompt_uses_trusted_actor(self):
        result = self.inspect().json()
        self.assertEqual(result["decision"], "ALLOW")
        self.assertTrue(result["send_allowed"])
        self.assertEqual(result["actor"], "user@example.test")

    def test_auditor_cannot_submit_or_manage_users(self):
        self.assertEqual(self.inspect(role="auditor").status_code, 403)
        self.assertEqual(self.client.get("/users", headers=self.accounts["auditor"]).status_code, 403)

    def test_users_cannot_read_organization_audit(self):
        for route in ("/audit", "/audit/events", "/reports/export", "/security/changes"):
            self.assertEqual(self.client.get(route, headers=self.accounts["user"]).status_code, 403)

    def test_disallowed_provider_denied_before_inspection(self):
        with patch.object(gateway, "inspect_prompt") as detector:
            self.assertEqual(self.inspect(service="Unapproved AI").status_code, 403)
            detector.assert_not_called()

    def test_credentials_always_block_and_never_return_prompt(self):
        result = self.inspect("password=FictionalPass123!").json()
        self.assertEqual(result["decision"], "BLOCK")
        self.assertFalse(result["send_allowed"])
        self.assertEqual(result["maskedOutput"], "")
        self.assertNotIn("FictionalPass123!", str(result))

    def test_pii_fully_replaced(self):
        result = self.inspect("Email fictional.person@example.test for details").json()
        self.assertEqual(result["decision"], "SANITIZE")
        self.assertNotIn("fictional.person", str(result))
        self.assertIn("[REDACTED]", result["maskedOutput"])

    def test_disabled_and_unmatched_rules_fail_closed(self):
        policy = self.policy()
        policy["rules"] = []
        self.assertEqual(self.save(policy).status_code, 200)
        self.assertEqual(self.inspect("hello@example.test").json()["decision"], "BLOCK")
        self.assertEqual(self.inspect("password=FictionalPass123!").json()["decision"], "BLOCK")

    def test_policy_validation_and_admin_permissions(self):
        policy = self.policy()
        self.assertEqual(self.save(policy, "user").status_code, 403)
        policy["rules"][0]["action"] = "ALLOW"
        self.assertEqual(self.save(policy).status_code, 422)

    def test_policy_conflict_rejected_and_history_persisted(self):
        policy = self.policy()
        self.assertEqual(self.save(policy).json()["version"], 2)
        self.assertEqual(self.save(policy).status_code, 409)
        history = self.client.get("/security/changes", headers=self.accounts["auditor"]).json()
        self.assertEqual(history[0]["action"], "POLICY_UPDATED")

    def test_block_takes_precedence_over_sanitize(self):
        policy = self.policy()
        policy["rules"].append(dict(policy["rules"][2], id="pii-block", action="BLOCK"))
        self.save(policy)
        self.assertEqual(self.inspect("hello@example.test").json()["decision"], "BLOCK")

    def test_self_approval_and_unauthorized_review_denied(self):
        identifier = self.pending()
        self.assertEqual(self.decide(identifier, "user").status_code, 403)
        with gateway.connect() as db:
            db.execute("UPDATE users SET role='approver' WHERE id='user'")
        self.assertEqual(self.decide(identifier, "user").status_code, 403)

    def test_approval_is_one_use_and_owned(self):
        identifier = self.pending()
        self.assertEqual(self.consume(identifier).status_code, 409)
        self.assertEqual(self.decide(identifier).status_code, 200)
        self.assertEqual(self.consume(identifier, "admin").status_code, 404)
        result = self.consume(identifier)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json()["sanitized_prompt"], "[REDACTED]")
        self.assertEqual(self.consume(identifier).status_code, 409)

    def test_expired_approval_cannot_be_reviewed(self):
        identifier = self.pending()
        with gateway.connect() as db:
            db.execute("UPDATE security_approvals SET expires=0 WHERE id=?", (identifier,))
        self.assertEqual(self.decide(identifier).status_code, 409)

    def test_policy_change_invalidates_approved_release(self):
        identifier = self.pending()
        self.decide(identifier)
        self.save(self.policy())
        self.assertEqual(self.consume(identifier).status_code, 409)

    def test_rejected_approval_cannot_be_consumed(self):
        identifier = self.pending()
        self.decide(identifier, decision="REJECTED")
        self.assertEqual(self.consume(identifier).status_code, 409)

    def test_logout_revokes_session(self):
        self.assertEqual(self.client.post("/auth/logout", headers=self.accounts["user"]).status_code, 200)
        self.assertEqual(self.client.get("/auth/me", headers=self.accounts["user"]).status_code, 401)

    def test_deleted_user_session_is_rejected(self):
        self.assertEqual(self.client.delete("/admin/users/user", headers=self.accounts["admin"]).status_code, 200)
        self.assertEqual(self.inspect().status_code, 401)

    def test_role_changes_and_disable_revoke_sessions(self):
        self.assertEqual(self.client.patch("/admin/users/user", headers=self.accounts["admin"], json={"role": "auditor", "active": False}).status_code, 200)
        self.assertEqual(self.inspect().status_code, 401)
        login = self.client.post("/auth/login", json={"email": "user@example.test", "password": "FictionalPass123!"})
        self.assertEqual(login.status_code, 401)

    def test_admin_cannot_remove_own_access(self):
        self.assertEqual(self.client.delete("/admin/users/admin", headers=self.accounts["admin"]).status_code, 400)
        self.assertEqual(self.client.patch("/admin/users/admin", headers=self.accounts["admin"], json={"role": "user", "active": True}).status_code, 400)

    def test_expired_and_forged_tokens_denied(self):
        self.assertEqual(self.client.get("/auth/me", headers={"Authorization": "Bearer forged.token"}).status_code, 401)
        with gateway.connect() as db:
            db.execute("UPDATE security_sessions SET expires=0 WHERE user_id='user'")
        self.assertEqual(self.inspect().status_code, 401)

    def test_session_database_contains_hash_not_token(self):
        token = self.accounts["user"]["Authorization"].split()[1]
        with gateway.connect() as db:
            row = db.execute("SELECT token_hash FROM security_sessions WHERE user_id='user'").fetchone()
        self.assertEqual(row[0], hashlib.sha256(token.encode()).hexdigest())
        self.assertNotEqual(row[0], token)

    def test_public_registration_never_creates_admin(self):
        result = self.client.post("/auth/register", json={"name": "Synthetic", "email": "new@example.test", "password": "FictionalPass123!", "role": "admin"})
        self.assertEqual(result.status_code, 201)
        self.assertEqual(result.json()["user"]["role"], "user")

    def test_bruteforce_throttling(self):
        for _ in range(5):
            self.assertEqual(self.client.post("/auth/login", json={"email": "user@example.test", "password": "wrong"}).status_code, 401)
        self.assertEqual(self.client.post("/auth/login", json={"email": "user@example.test", "password": "FictionalPass123!"}).status_code, 429)

    def test_migration_preserves_existing_accounts_and_audit(self):
        gateway.init_db()
        gateway.init_db()
        self.assertEqual(self.client.get("/auth/me", headers=self.accounts["admin"]).status_code, 200)

    def test_password_change_revokes_existing_sessions(self):
        response = self.client.post("/auth/password", headers=self.accounts["user"], json={"current_password": "FictionalPass123!", "new_password": "AnotherFictionalPass123!"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.inspect().status_code, 401)
        self.assertEqual(self.client.post("/auth/login", json={"email": "user@example.test", "password": "AnotherFictionalPass123!"}).status_code, 200)

    def test_admin_password_reset_revokes_sessions(self):
        payload = {"new_password": "AnotherFictionalPass123!"}
        self.assertEqual(self.client.post("/admin/users/admin/password", headers=self.accounts["user"], json=payload).status_code, 403)
        self.assertEqual(self.client.post("/admin/users/user/password", headers=self.accounts["admin"], json=payload).status_code, 200)
        self.assertEqual(self.inspect().status_code, 401)

    def test_legacy_password_is_upgraded_on_login(self):
        salt = "0"*32
        legacy = salt+"$"+hashlib.pbkdf2_hmac("sha256", b"FictionalPass123!", salt.encode(), 120000).hex()
        with gateway.connect() as db:
            db.execute("UPDATE users SET password_hash=? WHERE id='user'", (legacy,))
        self.assertEqual(self.client.post("/auth/login", json={"email": "user@example.test", "password": "FictionalPass123!"}).status_code, 200)
        with gateway.connect() as db:
            self.assertTrue(db.execute("SELECT password_hash FROM users WHERE id='user'").fetchone()[0].startswith("600000$"))

    def test_remote_payload_excludes_original_prompt(self):
        import asyncio
        from unittest.mock import AsyncMock, MagicMock
        response = MagicMock()
        response.json.return_value = {"id": "remote-id"}
        client = AsyncMock()
        client.post.return_value = response
        with patch.object(gateway, "REMOTE_AUDIT_API_URL", "https://audit.example.test/events"), patch.object(gateway.httpx, "AsyncClient") as factory:
            factory.return_value.__aenter__.return_value = client
            event = gateway.inspect_prompt(gateway.PromptInspectionIn(actor="test", service="ChatGPT Enterprise", prompt="synthetic"))
            event.originalPrompt = "SHOULD_NOT_LEAVE"
            asyncio.run(gateway.write_remote(event))
            self.assertNotIn("originalPrompt", client.post.call_args.kwargs["json"])

    def test_validation_does_not_echo_password_or_prompt(self):
        response = self.client.post("/auth/register", json={"name": "Test", "email": "bad", "password": "Secret!"})
        self.assertEqual(response.status_code, 422)
        self.assertNotIn("Secret!", response.text)
        response = self.inspect("x" * 10001)
        self.assertEqual(response.status_code, 422)
        self.assertNotIn("xxx", response.text)

    def test_invalid_policy_ranges_duplicates_and_providers(self):
        for change in ({"min_score": 99, "max_score": 1}, {"services": ["Unapproved AI"]}, {"category": "unknown"}):
            policy = self.policy()
            policy["rules"][1].update(change)
            self.assertEqual(self.save(policy).status_code, 422)
        policy = self.policy()
        policy["rules"].append(policy["rules"][0])
        self.assertEqual(self.save(policy).status_code, 422)

    def test_disabled_pii_rule_blocks(self):
        policy = self.policy()
        policy["rules"][2]["enabled"] = False
        self.save(policy)
        self.assertEqual(self.inspect("hello@example.test").json()["decision"], "BLOCK")

    def test_sqlite_migration_from_original_schema(self):
        import sqlite3
        old_path = gateway.DB_PATH
        gateway.DB_PATH = Path(self.temp.name) / "legacy.sqlite3"
        db = sqlite3.connect(gateway.DB_PATH)
        db.execute("CREATE TABLE users(id TEXT PRIMARY KEY,name TEXT,email TEXT UNIQUE,password_hash TEXT,role TEXT,created_at TEXT)")
        db.execute("INSERT INTO users VALUES ('legacy','Legacy','legacy@example.test',?,'Security Admin','test')", (self.password_digest,))
        db.commit()
        db.close()
        try:
            gateway.init_db()
            gateway.init_db()
            with gateway.connect() as connection:
                row = connection.execute("SELECT * FROM users WHERE id='legacy'").fetchone()
                self.assertEqual(row["role"], "admin")
                self.assertEqual(row["active"], 1)
                self.assertEqual(row["password_hash"], self.password_digest)
        finally:
            gateway.DB_PATH = old_path


if __name__ == "__main__":
    unittest.main()
