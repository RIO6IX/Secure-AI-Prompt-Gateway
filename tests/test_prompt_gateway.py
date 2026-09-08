"""End-to-end tests for the local prompt-security pipeline.

Run from the project root with:

    python -m unittest tests.test_prompt_gateway -v

All examples are fictional. The tests use the real Regex detector and a
deterministic GLiNER substitute so they remain fast and repeatable.
"""

import unittest

from app.logging.audit_logger import AuditLogger
from app.prompt_gateway import PromptGateway, PromptProcessingError


class StubGLiNERDetector:
    """Return configured fictional entities at their real prompt positions."""

    def __init__(self, entities: list[tuple[str, str, float]] | None = None):
        self.entities = entities or []

    def detect(self, text: str) -> list[dict]:
        detections = []

        for value, label, score in self.entities:
            start = text.index(value)
            detections.append(
                {
                    "label": label,
                    "text": value,
                    "start": start,
                    "end": start + len(value),
                    "score": score,
                    "source": "gliner",
                }
            )

        return detections


class FailingGLiNERDetector:
    """Simulate a local entity-model failure."""

    @staticmethod
    def detect(text: str) -> list[dict]:
        raise RuntimeError("fictional sensitive value: HiddenDemoValue123")


class PromptGatewayEndToEndTests(unittest.TestCase):
    def setUp(self) -> None:
        self.loggers: list[AuditLogger] = []

    def tearDown(self) -> None:
        for logger in self.loggers:
            logger.close()

    def make_gateway(
        self,
        entities: list[tuple[str, str, float]] | None = None,
        *,
        gliner_detector=None,
    ) -> tuple[PromptGateway, AuditLogger]:
        logger = AuditLogger(":memory:")
        self.loggers.append(logger)
        detector = (
            StubGLiNERDetector(entities)
            if gliner_detector is None
            else gliner_detector
        )
        gateway = PromptGateway(
            gliner_detector=detector,
            audit_logger=logger,
        )
        return gateway, logger

    @staticmethod
    def labels(result: dict) -> list[str]:
        return [item["label"] for item in result["detections"]]

    def test_clean_prompt_is_allowed_unchanged(self) -> None:
        prompt = "Explain how symmetric encryption works."
        gateway, _ = self.make_gateway()

        result = gateway.process_prompt(prompt, user_id="EMP2048")

        self.assertEqual(result["decision"], "ALLOW")
        self.assertEqual(result["risk"]["level"], "NONE")
        self.assertEqual(result["detections"], [])
        self.assertIsNone(result["sanitization"])
        self.assertEqual(result["prompt_for_external_ai"], prompt)

    def test_empty_prompt_is_allowed_safely(self) -> None:
        gateway, _ = self.make_gateway()

        result = gateway.process_prompt("", user_id="EMP2048")

        self.assertEqual(result["decision"], "ALLOW")
        self.assertEqual(result["prompt_for_external_ai"], "")
        self.assertEqual(result["audit_event"]["total_detections"], 0)

    def test_pii_only_prompt_is_sanitized(self) -> None:
        prompt = "Contact fictional.user@example.org for the demo."
        gateway, _ = self.make_gateway()

        result = gateway.process_prompt(prompt, user_id="EMP2048")

        self.assertEqual(result["decision"], "SANITIZE")
        self.assertEqual(self.labels(result), ["EMAIL"])
        self.assertEqual(
            result["prompt_for_external_ai"],
            "Contact [EMAIL_1] for the demo.",
        )
        self.assertNotIn("fictional.user", str(result["detections"]))

    def test_financial_prompt_is_sanitized(self) -> None:
        prompt = "The fictional travel budget is LKR 12,750.50."
        gateway, _ = self.make_gateway()

        result = gateway.process_prompt(prompt, user_id="EMP2048")

        self.assertEqual(result["decision"], "SANITIZE")
        self.assertEqual(result["risk"]["level"], "HIGH")
        self.assertEqual(self.labels(result), ["LKR_AMOUNT"])
        self.assertIn("[LKR_AMOUNT_1]", result["prompt_for_external_ai"])

    def test_credential_prompt_is_blocked(self) -> None:
        prompt = "Password = FictionalPass123!"
        gateway, _ = self.make_gateway()

        result = gateway.process_prompt(prompt, user_id="EMP2048")

        self.assertEqual(result["decision"], "BLOCK")
        self.assertEqual(result["risk"]["level"], "CRITICAL")
        self.assertIsNone(result["prompt_for_external_ai"])
        self.assertIsNone(result["sanitization"])

    def test_natural_password_phrase_is_blocked(self) -> None:
        prompt = "My password is FictionalPass123!"
        gateway, _ = self.make_gateway()

        result = gateway.process_prompt(prompt, user_id="EMP2048")

        self.assertEqual(result["decision"], "BLOCK")
        self.assertEqual(result["risk"]["level"], "CRITICAL")
        self.assertEqual(self.labels(result), ["PASSWORD"])
        self.assertIsNone(result["prompt_for_external_ai"])

    def test_mixed_regex_and_gliner_results_are_sanitized(self) -> None:
        prompt = (
            "Nimali Jayawardena at Serendib Research uses "
            "nimali.j@example.org."
        )
        entities = [
            ("Nimali Jayawardena", "person", 0.95),
            ("Serendib Research", "organization", 0.93),
        ]
        gateway, _ = self.make_gateway(entities)

        result = gateway.process_prompt(prompt, user_id="EMP2048")

        self.assertEqual(result["decision"], "SANITIZE")
        self.assertEqual(
            set(self.labels(result)),
            {"PERSON", "ORGANIZATION", "EMAIL"},
        )
        safe_prompt = result["prompt_for_external_ai"]
        self.assertIn("[PERSON_1]", safe_prompt)
        self.assertIn("[ORGANIZATION_1]", safe_prompt)
        self.assertIn("[EMAIL_1]", safe_prompt)

    def test_regex_result_wins_over_overlapping_gliner_result(self) -> None:
        prompt = "Email kasun.perera@example.com for the fictional case."
        gateway, _ = self.make_gateway(
            [("kasun.perera", "person", 0.99)]
        )

        result = gateway.process_prompt(prompt, user_id="EMP2048")

        self.assertEqual(self.labels(result), ["EMAIL"])
        self.assertEqual(result["detections"][0]["source"], "regex")
        self.assertIn("[EMAIL_1]", result["prompt_for_external_ai"])
        self.assertNotIn("[PERSON_1]", result["prompt_for_external_ai"])

    def test_unicode_and_sri_lankan_context_are_preserved(self) -> None:
        prompt = "පරීක්ෂණණය Colombo කාර්යාලයට 0771234567 අමතන්න."
        gateway, _ = self.make_gateway([("Colombo", "city", 0.91)])

        result = gateway.process_prompt(prompt, user_id="EMP2048")

        self.assertEqual(result["decision"], "SANITIZE")
        self.assertEqual(set(self.labels(result)), {"CITY", "PHONE"})
        safe_prompt = result["prompt_for_external_ai"]
        self.assertIn("පරීක්ෂණණය", safe_prompt)
        self.assertIn("[CITY_1]", safe_prompt)
        self.assertIn("[PHONE_1]", safe_prompt)

    def test_very_long_prompt_is_processed_without_truncation(self) -> None:
        prompt = ("Fictional project context. " * 1000) + (
            "Contact long.test@example.org."
        )
        gateway, _ = self.make_gateway()

        result = gateway.process_prompt(prompt, user_id="EMP2048")

        self.assertEqual(result["decision"], "SANITIZE")
        self.assertEqual(self.labels(result), ["EMAIL"])
        safe_prompt = result["prompt_for_external_ai"]
        self.assertTrue(safe_prompt.startswith("Fictional project context."))
        self.assertTrue(safe_prompt.endswith("Contact [EMAIL_1]."))

    def test_success_audit_contains_metadata_only(self) -> None:
        prompt = "Contact fictional.audit@example.org."
        gateway, logger = self.make_gateway()

        result = gateway.process_prompt(prompt, user_id="EMP2048")
        audit_event = logger.get_event(result["audit_event"]["event_id"])

        self.assertIsNotNone(audit_event)
        self.assertEqual(audit_event["detected_labels"], {"EMAIL": 1})
        self.assertEqual(audit_event["detector_sources"], ["regex"])
        self.assertFalse(audit_event["raw_prompt_stored"])
        self.assertNotIn("fictional.audit", str(audit_event))

    def test_detection_failure_blocks_safely_and_logs_safe_code(self) -> None:
        prompt = "HiddenDemoValue123 must never appear in failure logs."
        gateway, logger = self.make_gateway(
            gliner_detector=FailingGLiNERDetector()
        )

        with self.assertRaises(PromptProcessingError) as context:
            gateway.process_prompt(prompt, user_id="EMP2048")

        self.assertNotIn("HiddenDemoValue123", str(context.exception))
        row = logger._connection.execute(
            "SELECT event_id FROM audit_events"
        ).fetchone()
        self.assertIsNotNone(row)
        audit_event = logger.get_event(row["event_id"])
        self.assertEqual(audit_event["decision"], "BLOCK")
        self.assertFalse(audit_event["success"])
        self.assertEqual(
            audit_event["failure_code"],
            "LOCAL_PROCESSING_ERROR",
        )
        database_dump = "\n".join(logger._connection.iterdump())
        self.assertNotIn("HiddenDemoValue123", database_dump)

    def test_gateway_response_never_exposes_raw_detection_text(self) -> None:
        prompt = "Fictional Person uses private.demo@example.org."
        gateway, _ = self.make_gateway(
            [("Fictional Person", "person", 0.96)]
        )

        result = gateway.process_prompt(prompt, user_id="EMP2048")

        for detection in result["detections"]:
            self.assertNotIn("text", detection)
        self.assertNotIn(
            "private.demo@example.org",
            str(result["detections"]),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
