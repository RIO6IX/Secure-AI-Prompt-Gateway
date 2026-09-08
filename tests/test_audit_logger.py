"""
Tests for AuditLogger.

Run from the project root with:

    python -m unittest tests.test_audit_logger -v
"""

from copy import deepcopy
from datetime import datetime, timezone
import sqlite3
import unittest
from uuid import UUID

from app.logging.audit_logger import AuditLogger, AuditStorageError


EXPECTED_RECORD_FIELDS = {
    "event_id",
    "timestamp",
    "user_id",
    "role",
    "decision",
    "risk_level",
    "detected_labels",
    "total_detections",
    "detector_sources",
    "sanitized",
    "blocked",
    "external_provider",
    "processing_time_ms",
    "success",
    "failure_code",
    "raw_prompt_stored",
}


class AuditLoggerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.logger: AuditLogger | None = AuditLogger(":memory:")

    def tearDown(self) -> None:
        if self.logger is not None:
            self.logger.close()

    def log_sample(self, **overrides) -> dict:
        values = {
            "user_id": "EMP2048",
            "role": "EMPLOYEE",
            "decision": "BLOCK",
            "risk_level": "CRITICAL",
            "detected_labels": {"EMAIL": 1, "PASSWORD": 1},
            "detector_sources": ["regex", "gliner"],
            "processing_time_ms": 18.5,
            "success": True,
        }
        values.update(overrides)
        assert self.logger is not None
        return self.logger.log_event(**values)

    def test_audit_record_creation_and_required_fields(self) -> None:
        record = self.log_sample()

        self.assertEqual(set(record), EXPECTED_RECORD_FIELDS)
        self.assertEqual(record["decision"], "BLOCK")
        self.assertEqual(record["risk_level"], "CRITICAL")
        self.assertEqual(record["total_detections"], 2)

    def test_event_id_is_a_valid_uuid(self) -> None:
        record = self.log_sample()

        parsed_id = UUID(record["event_id"])

        self.assertEqual(str(parsed_id), record["event_id"])

    def test_timestamp_is_valid_utc_iso_timestamp(self) -> None:
        record = self.log_sample()

        parsed_timestamp = datetime.fromisoformat(record["timestamp"])

        self.assertIsNotNone(parsed_timestamp.tzinfo)
        self.assertEqual(
            parsed_timestamp.utcoffset(),
            timezone.utc.utcoffset(parsed_timestamp),
        )

    def test_event_ids_are_unique(self) -> None:
        first = self.log_sample()
        second = self.log_sample(user_id="EMP4096")

        self.assertNotEqual(first["event_id"], second["event_id"])

    def test_stored_event_can_be_retrieved(self) -> None:
        stored = self.log_sample()
        assert self.logger is not None

        retrieved = self.logger.get_event(stored["event_id"])

        self.assertEqual(retrieved, stored)

    def test_missing_event_returns_none(self) -> None:
        assert self.logger is not None

        self.assertIsNone(
            self.logger.get_event(
                "00000000-0000-0000-0000-000000000000"
            )
        )

    def test_label_counts_and_sources_are_normalized(self) -> None:
        record = self.log_sample(
            detected_labels={"PERSON": 2, "EMAIL": 1},
            detector_sources=["regex", "gliner", "regex"],
        )

        self.assertEqual(
            record["detected_labels"],
            {"EMAIL": 1, "PERSON": 2},
        )
        self.assertEqual(record["total_detections"], 3)
        self.assertEqual(record["detector_sources"], ["gliner", "regex"])

    def test_decision_status_flags(self) -> None:
        cases = (
            ("ALLOW", "NONE", False, False),
            ("SANITIZE", "MEDIUM", True, False),
            ("BLOCK", "CRITICAL", False, True),
        )

        for decision, risk_level, sanitized, blocked in cases:
            with self.subTest(decision=decision):
                record = self.log_sample(
                    decision=decision,
                    risk_level=risk_level,
                    detected_labels=(
                        {} if decision == "ALLOW" else {"EMAIL": 1}
                    ),
                )
                self.assertEqual(record["sanitized"], sanitized)
                self.assertEqual(record["blocked"], blocked)

    def test_clean_event_supports_empty_detection_metadata(self) -> None:
        record = self.log_sample(
            decision="ALLOW",
            risk_level="NONE",
            detected_labels={},
            detector_sources=[],
        )

        self.assertEqual(record["total_detections"], 0)
        self.assertEqual(record["detected_labels"], {})
        self.assertEqual(record["detector_sources"], [])

    def test_raw_sensitive_values_are_not_stored(self) -> None:
        fictional_values = (
            "FictionalPass123!",
            "demo_API_key_123456789",
            "901234567V",
            "001234567890",
        )
        record = self.log_sample()
        assert self.logger is not None
        database_dump = "\n".join(self.logger._connection.iterdump())
        rendered_record = str(record)

        for fictional_value in fictional_values:
            self.assertNotIn(fictional_value, rendered_record)
            self.assertNotIn(fictional_value, database_dump)

    def test_schema_has_no_prompt_or_raw_value_columns(self) -> None:
        assert self.logger is not None
        columns = {
            row[1]
            for row in self.logger._connection.execute(
                "PRAGMA table_info(audit_events)"
            )
        }

        forbidden_columns = {
            "prompt",
            "original_prompt",
            "detection_text",
            "password",
            "api_key",
            "token",
            "nic",
            "bank_account",
            "credit_card",
        }
        self.assertFalse(columns & forbidden_columns)

    def test_raw_prompt_flag_is_false_and_database_constrained(self) -> None:
        record = self.log_sample()
        self.assertFalse(record["raw_prompt_stored"])
        assert self.logger is not None

        with self.assertRaises(sqlite3.IntegrityError):
            with self.logger._connection:
                self.logger._connection.execute(
                    """
                    UPDATE audit_events
                    SET raw_prompt_stored = 1
                    WHERE event_id = ?
                    """,
                    (record["event_id"],),
                )

    def test_logger_api_rejects_unexpected_prompt_argument(self) -> None:
        values = {
            "user_id": "EMP2048",
            "role": "EMPLOYEE",
            "decision": "BLOCK",
            "risk_level": "CRITICAL",
            "detected_labels": {"PASSWORD": 1},
            "detector_sources": ["regex"],
            "original_prompt": "Password = FictionalPass123!",
        }
        assert self.logger is not None

        with self.assertRaises(TypeError):
            self.logger.log_event(**values)  # type: ignore[arg-type]

    def test_failed_event_requires_safe_failure_code(self) -> None:
        failed = self.log_sample(
            success=False,
            failure_code="LOCAL_MODEL_ERROR",
        )

        self.assertFalse(failed["success"])
        self.assertEqual(failed["failure_code"], "LOCAL_MODEL_ERROR")

        for invalid_code in (None, "model error", "ERROR: raw value"):
            with self.subTest(invalid_code=invalid_code):
                with self.assertRaises(ValueError):
                    self.log_sample(
                        success=False,
                        failure_code=invalid_code,
                    )

    def test_invalid_metadata_is_rejected(self) -> None:
        invalid_overrides = (
            {"role": "UNKNOWN"},
            {"decision": "DELETE"},
            {"risk_level": "EXTREME"},
            {"detected_labels": {"person": 1}},
            {"detected_labels": {"EMAIL": 0}},
            {"detector_sources": ["external"]},
            {"processing_time_ms": -1},
        )

        for overrides in invalid_overrides:
            with self.subTest(overrides=overrides):
                with self.assertRaises((TypeError, ValueError)):
                    self.log_sample(**overrides)

    def test_input_metadata_is_not_modified(self) -> None:
        labels = {"PERSON": 2, "EMAIL": 1}
        sources = ["regex", "gliner", "regex"]
        labels_before = deepcopy(labels)
        sources_before = deepcopy(sources)

        self.log_sample(
            detected_labels=labels,
            detector_sources=sources,
        )

        self.assertEqual(labels, labels_before)
        self.assertEqual(sources, sources_before)

    def test_closed_database_raises_safe_storage_error(self) -> None:
        assert self.logger is not None
        self.logger.close()
        closed_logger = self.logger
        self.logger = None

        with self.assertRaises(AuditStorageError) as context:
            closed_logger.log_event(
                user_id="EMP2048",
                role="EMPLOYEE",
                decision="ALLOW",
                risk_level="NONE",
                detected_labels={},
                detector_sources=[],
            )

        self.assertEqual(
            str(context.exception),
            "Unable to store the audit event.",
        )

    def test_empty_dashboard_query_returns_safe_structure(self) -> None:
        assert self.logger is not None

        result = self.logger.query_events()

        self.assertEqual(result["events"], [])
        self.assertEqual(result["total"], 0)
        self.assertFalse(result["has_more"])
        self.assertEqual(
            result["summary"]["decisions"],
            {"ALLOW": 0, "BLOCK": 0, "SANITIZE": 0},
        )

    def test_dashboard_query_supports_pagination(self) -> None:
        self.log_sample(
            decision="ALLOW",
            risk_level="NONE",
            detected_labels={},
            detector_sources=[],
        )
        self.log_sample(
            decision="SANITIZE",
            risk_level="MEDIUM",
            detected_labels={"EMAIL": 1},
            detector_sources=["regex"],
        )
        self.log_sample()
        assert self.logger is not None

        first_page = self.logger.query_events(limit=2)
        second_page = self.logger.query_events(limit=2, offset=2)

        self.assertEqual(first_page["total"], 3)
        self.assertEqual(len(first_page["events"]), 2)
        self.assertTrue(first_page["has_more"])
        self.assertEqual(len(second_page["events"]), 1)
        self.assertFalse(second_page["has_more"])

    def test_dashboard_filters_and_summary_are_consistent(self) -> None:
        self.log_sample(
            user_id="EMP2048",
            decision="ALLOW",
            risk_level="NONE",
            detected_labels={},
            detector_sources=[],
        )
        self.log_sample(
            user_id="EMP4096",
            decision="SANITIZE",
            risk_level="MEDIUM",
            detected_labels={"EMAIL": 1},
            detector_sources=["regex"],
        )
        self.log_sample(user_id="EMP4096")
        assert self.logger is not None

        result = self.logger.query_events(user_id="EMP4096")

        self.assertEqual(result["total"], 2)
        self.assertEqual(
            {event["user_id"] for event in result["events"]},
            {"EMP4096"},
        )
        self.assertEqual(result["summary"]["decisions"]["BLOCK"], 1)
        self.assertEqual(result["summary"]["decisions"]["SANITIZE"], 1)

    def test_dashboard_results_contain_no_raw_sensitive_values(self) -> None:
        fictional_values = (
            "FictionalPass123!",
            "demo_API_key_123456789",
            "901234567V",
        )
        self.log_sample()
        assert self.logger is not None

        rendered_result = str(self.logger.query_events())

        for fictional_value in fictional_values:
            self.assertNotIn(fictional_value, rendered_result)

    def test_invalid_dashboard_query_is_rejected(self) -> None:
        assert self.logger is not None
        invalid_queries = (
            {"limit": 0},
            {"limit": 101},
            {"offset": -1},
            {"decision": "DELETE"},
            {"risk_level": "EXTREME"},
            {"user_id": ""},
        )

        for values in invalid_queries:
            with self.subTest(values=values):
                with self.assertRaises(ValueError):
                    self.logger.query_events(**values)

    def test_external_provider_success_updates_only_safe_metadata(self) -> None:
        event = self.log_sample(
            decision="ALLOW",
            risk_level="NONE",
            detected_labels={},
            detector_sources=[],
        )
        assert self.logger is not None

        updated = self.logger.update_external_outcome(
            event["event_id"],
            external_provider="groq",
            success=True,
        )

        self.assertEqual(updated["external_provider"], "groq")
        self.assertTrue(updated["success"])
        self.assertIsNone(updated["failure_code"])

    def test_external_provider_failure_uses_safe_code(self) -> None:
        event = self.log_sample(
            decision="SANITIZE",
            risk_level="MEDIUM",
            detected_labels={"EMAIL": 1},
            detector_sources=["regex"],
        )
        assert self.logger is not None

        updated = self.logger.update_external_outcome(
            event["event_id"],
            external_provider="groq",
            success=False,
            failure_code="EXTERNAL_PROVIDER_ERROR",
        )

        self.assertEqual(updated["decision"], "SANITIZE")
        self.assertFalse(updated["success"])
        self.assertEqual(updated["failure_code"], "EXTERNAL_PROVIDER_ERROR")

    def test_invalid_external_outcome_is_rejected(self) -> None:
        event = self.log_sample()
        assert self.logger is not None

        with self.assertRaises(ValueError):
            self.logger.update_external_outcome(
                event["event_id"],
                external_provider="groq",
                success=False,
                failure_code="raw provider failure details",
            )

        with self.assertRaises(ValueError):
            self.logger.update_external_outcome(
                "00000000-0000-0000-0000-000000000000",
                external_provider="groq",
                success=True,
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
