"""Tests for local password hashing, sessions, and roles."""

from datetime import datetime, timedelta, timezone
import unittest

from app.auth import AuthService, InvalidCredentialsError, InvalidSessionError


class AuthServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.auth = AuthService(":memory:", hash_iterations=1_000)

    def tearDown(self) -> None:
        self.auth.close()

    def create_employee(
        self,
        user_id: str = "EMP2048",
        password: str = "FictionalPass123!",
    ) -> dict:
        return self.auth.create_user(user_id, password, "EMPLOYEE")

    def test_create_user_returns_safe_metadata(self) -> None:
        password = "FictionalPass123!"

        result = self.create_employee(password=password)

        self.assertEqual(
            set(result),
            {"user_id", "role", "active", "created_at"},
        )
        self.assertEqual(result["user_id"], "EMP2048")
        self.assertEqual(result["role"], "EMPLOYEE")
        self.assertNotIn(password, str(result))

    def test_database_never_contains_raw_password(self) -> None:
        password = "FictionalPass123!"
        self.create_employee(password=password)

        database_dump = "\n".join(self.auth._connection.iterdump())

        self.assertNotIn(password, database_dump)
        columns = {
            row[1]
            for row in self.auth._connection.execute(
                "PRAGMA table_info(users)"
            )
        }
        self.assertNotIn("password", columns)
        self.assertIn("password_hash", columns)
        self.assertIn("password_salt", columns)

    def test_same_password_uses_unique_salts_and_hashes(self) -> None:
        password = "SharedFictionalPass123!"
        self.create_employee("EMP2048", password)
        self.create_employee("EMP4096", password)

        rows = self.auth._connection.execute(
            "SELECT password_hash, password_salt FROM users ORDER BY user_id"
        ).fetchall()

        self.assertNotEqual(rows[0]["password_salt"], rows[1]["password_salt"])
        self.assertNotEqual(rows[0]["password_hash"], rows[1]["password_hash"])

    def test_correct_credentials_create_valid_session(self) -> None:
        self.create_employee()

        session = self.auth.authenticate("EMP2048", "FictionalPass123!")
        identity = self.auth.validate_session(session["access_token"])

        self.assertEqual(session["token_type"], "Bearer")
        self.assertEqual(identity["user_id"], "EMP2048")
        self.assertEqual(identity["role"], "EMPLOYEE")

    def test_wrong_and_unknown_credentials_use_same_safe_error(self) -> None:
        self.create_employee()

        cases = (
            ("EMP2048", "WrongFictionalPass123!"),
            ("EMP9999", "WrongFictionalPass123!"),
        )

        for user_id, password in cases:
            with self.subTest(user_id=user_id):
                with self.assertRaises(InvalidCredentialsError) as context:
                    self.auth.authenticate(user_id, password)
                self.assertEqual(
                    str(context.exception),
                    "Invalid user ID or password.",
                )

    def test_raw_session_token_is_not_stored(self) -> None:
        self.create_employee()

        session = self.auth.authenticate("EMP2048", "FictionalPass123!")
        database_dump = "\n".join(self.auth._connection.iterdump())

        self.assertNotIn(session["access_token"], database_dump)

    def test_each_login_receives_a_unique_token(self) -> None:
        self.create_employee()

        first = self.auth.authenticate("EMP2048", "FictionalPass123!")
        second = self.auth.authenticate("EMP2048", "FictionalPass123!")

        self.assertNotEqual(first["access_token"], second["access_token"])

    def test_logout_invalidates_session(self) -> None:
        self.create_employee()
        session = self.auth.authenticate("EMP2048", "FictionalPass123!")

        self.auth.logout(session["access_token"])

        with self.assertRaises(InvalidSessionError):
            self.auth.validate_session(session["access_token"])

    def test_expired_session_is_rejected_and_removed(self) -> None:
        self.create_employee()
        session = self.auth.authenticate("EMP2048", "FictionalPass123!")
        expired_at = (
            datetime.now(timezone.utc) - timedelta(minutes=1)
        ).isoformat()
        with self.auth._connection:
            self.auth._connection.execute(
                "UPDATE sessions SET expires_at = ?",
                (expired_at,),
            )

        with self.assertRaises(InvalidSessionError):
            self.auth.validate_session(session["access_token"])

        remaining = self.auth._connection.execute(
            "SELECT COUNT(*) FROM sessions"
        ).fetchone()[0]
        self.assertEqual(remaining, 0)

    def test_admin_role_is_preserved_in_session(self) -> None:
        self.auth.create_user(
            "ADMIN01",
            "FictionalAdminPass123!",
            "ADMIN",
        )

        session = self.auth.authenticate(
            "ADMIN01",
            "FictionalAdminPass123!",
        )

        self.assertEqual(session["role"], "ADMIN")

    def test_disabling_user_revokes_sessions(self) -> None:
        self.create_employee()
        session = self.auth.authenticate("EMP2048", "FictionalPass123!")

        self.auth.set_user_active("EMP2048", False)

        with self.assertRaises(InvalidSessionError):
            self.auth.validate_session(session["access_token"])
        with self.assertRaises(InvalidCredentialsError):
            self.auth.authenticate("EMP2048", "FictionalPass123!")

    def test_invalid_user_data_and_duplicate_are_rejected(self) -> None:
        self.create_employee()

        invalid_cases = (
            ("x", "FictionalPass123!", "EMPLOYEE"),
            ("EMP4096", "short", "EMPLOYEE"),
            ("EMP4096", "FictionalPass123!", "SYSTEM"),
            ("EMP2048", "AnotherFictional123!", "EMPLOYEE"),
        )

        for user_id, password, role in invalid_cases:
            with self.subTest(user_id=user_id, role=role):
                with self.assertRaises((TypeError, ValueError)):
                    self.auth.create_user(user_id, password, role)


if __name__ == "__main__":
    unittest.main(verbosity=2)
