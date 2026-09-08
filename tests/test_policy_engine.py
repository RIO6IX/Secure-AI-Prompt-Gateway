"""
Tests for PolicyEngine.

Run from the project root with:

    python -m unittest tests.test_policy_engine -v
"""

from copy import deepcopy
import unittest

from app.policies.policy_engine import (
    MANDATORY_BLOCK_LABELS,
    PolicyEngine,
)
from app.processing.risk_scorer import RiskScorer


def make_detection(
    label: str,
    score: float,
    text: str = "fictional-sensitive-value",
) -> dict:
    """Create a fictional normalized detection for policy tests."""

    return {
        "label": label,
        "score": score,
        "text": text,
    }


class PolicyEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scorer = RiskScorer()
        self.engine = PolicyEngine()

    def evaluate(
        self,
        detections: list[dict],
        engine: PolicyEngine | None = None,
    ) -> dict:
        selected_engine = engine or self.engine
        risk_result = self.scorer.score(detections)
        return selected_engine.evaluate(risk_result, detections)

    def test_clean_prompt_is_allowed(self) -> None:
        result = self.evaluate([])

        self.assertEqual(result["decision"], "ALLOW")
        self.assertEqual(result["risk_level"], "NONE")
        self.assertEqual(result["triggering_labels"], [])
        self.assertFalse(result["user_confirmation_required"])

    def test_permitted_low_risk_information_is_allowed(self) -> None:
        detections = [
            make_detection("URL", 0.95),
            make_detection("CITY", 0.90),
        ]

        result = self.evaluate(detections)

        self.assertEqual(result["decision"], "ALLOW")
        self.assertEqual(result["risk_level"], "LOW")
        self.assertFalse(result["user_confirmation_required"])

    def test_email_is_sanitized(self) -> None:
        result = self.evaluate([
            make_detection("EMAIL", 0.98, "kasun@example.com"),
        ])

        self.assertEqual(result["decision"], "SANITIZE")
        self.assertEqual(result["risk_level"], "MEDIUM")
        self.assertTrue(result["user_confirmation_required"])

    def test_nic_is_sanitized_by_default(self) -> None:
        result = self.evaluate([
            make_detection("NIC", 0.99, "901234567V"),
        ])

        self.assertEqual(result["decision"], "SANITIZE")
        self.assertEqual(result["risk_level"], "HIGH")
        self.assertTrue(result["user_confirmation_required"])

    def test_nic_can_be_blocked_by_configuration(self) -> None:
        configured_engine = PolicyEngine(
            additional_blocked_labels={"NIC"}
        )

        result = self.evaluate(
            [make_detection("NIC", 0.99, "901234567V")],
            configured_engine,
        )

        self.assertEqual(result["decision"], "BLOCK")
        self.assertFalse(result["user_confirmation_required"])

    def test_password_is_blocked(self) -> None:
        result = self.evaluate([
            make_detection("PASSWORD", 0.99, "FictionalPass123!"),
        ])

        self.assertEqual(result["decision"], "BLOCK")
        self.assertEqual(result["risk_level"], "CRITICAL")
        self.assertFalse(result["user_confirmation_required"])

    def test_api_key_is_blocked(self) -> None:
        result = self.evaluate([
            make_detection(
                "API_KEY",
                0.99,
                "demo_API_key_123456789",
            ),
        ])

        self.assertEqual(result["decision"], "BLOCK")

    def test_token_and_jwt_are_blocked(self) -> None:
        for label in ("TOKEN", "JWT"):
            with self.subTest(label=label):
                result = self.evaluate([
                    make_detection(label, 0.99),
                ])
                self.assertEqual(result["decision"], "BLOCK")

    def test_all_mandatory_labels_remain_blocked(self) -> None:
        engine = PolicyEngine(additional_blocked_labels=set())

        self.assertTrue(
            MANDATORY_BLOCK_LABELS <= engine.blocked_labels
        )

    def test_multiple_medium_detections_are_sanitized(self) -> None:
        detections = [
            make_detection("PERSON", 0.90),
            make_detection("EMAIL", 0.90),
        ]

        result = self.evaluate(detections)

        self.assertEqual(result["decision"], "SANITIZE")
        self.assertEqual(result["risk_level"], "MEDIUM")

    def test_critical_combination_is_blocked(self) -> None:
        detections = [
            make_detection(label, 0.90)
            for label in (
                "PERSON",
                "EMAIL",
                "PHONE",
                "EMPLOYEE_ID",
                "CUSTOMER_ID",
            )
        ]

        result = self.evaluate(detections)

        self.assertEqual(result["risk_level"], "CRITICAL")
        self.assertEqual(result["decision"], "BLOCK")

    def test_output_contains_required_fields(self) -> None:
        result = self.evaluate([
            make_detection("EMAIL", 0.98),
        ])

        self.assertEqual(
            set(result),
            {
                "decision",
                "risk_level",
                "reason",
                "triggering_labels",
                "user_confirmation_required",
            },
        )

    def test_triggering_labels_are_unique_and_sorted(self) -> None:
        detections = [
            make_detection("PERSON", 0.90),
            make_detection("EMAIL", 0.90),
            make_detection("EMAIL", 0.85),
        ]

        result = self.evaluate(detections)

        self.assertEqual(
            result["triggering_labels"],
            ["EMAIL", "PERSON"],
        )

    def test_policy_output_does_not_include_raw_values(self) -> None:
        fictional_password = "FictionalPass123!"
        fictional_api_key = "demo_API_key_123456789"
        detections = [
            make_detection("PASSWORD", 0.99, fictional_password),
            make_detection("API_KEY", 0.99, fictional_api_key),
        ]

        rendered_result = str(self.evaluate(detections))

        self.assertNotIn(fictional_password, rendered_result)
        self.assertNotIn(fictional_api_key, rendered_result)

    def test_inputs_are_not_modified(self) -> None:
        detections = [
            make_detection("EMAIL", 0.98, "kasun@example.com"),
        ]
        risk_result = self.scorer.score(detections)
        detections_before = deepcopy(detections)
        risk_before = deepcopy(risk_result)

        self.engine.evaluate(risk_result, detections)

        self.assertEqual(detections, detections_before)
        self.assertEqual(risk_result, risk_before)

    def test_unknown_and_unnormalized_labels_are_rejected(self) -> None:
        risk_result = {
            "score": 20,
            "level": "MEDIUM",
        }

        for invalid_label in ("person", "UNKNOWN_LABEL"):
            with self.subTest(invalid_label=invalid_label):
                with self.assertRaises(ValueError):
                    self.engine.evaluate(
                        risk_result,
                        [{"label": invalid_label}],
                    )

    def test_invalid_risk_and_configuration_are_rejected(self) -> None:
        email_detection = [{"label": "EMAIL"}]

        with self.assertRaises(ValueError):
            self.engine.evaluate(
                {"score": 20, "level": "HIGH"},
                email_detection,
            )

        with self.assertRaises(ValueError):
            self.engine.evaluate(
                {"score": 20, "level": "MEDIUM"},
                [],
            )

        with self.assertRaises(TypeError):
            PolicyEngine(additional_blocked_labels=[])  # type: ignore[arg-type]

        with self.assertRaises(ValueError):
            PolicyEngine(additional_blocked_labels={"UNKNOWN_LABEL"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
