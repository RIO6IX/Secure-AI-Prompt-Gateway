"""
Tests for RiskScorer.

Run from the project root with:

    python -m unittest tests.test_risk_scorer -v
"""

from copy import deepcopy
import unittest

from app.processing.label_normalizer import CANONICAL_LABELS
from app.processing.risk_scorer import LABEL_SEVERITY, RiskScorer


def make_detection(
    label: str,
    score: float,
    text: str = "fictional-sensitive-value",
) -> dict:
    """Create the fields needed by the risk scorer."""

    return {
        "label": label,
        "score": score,
        "text": text,
    }


class RiskScorerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scorer = RiskScorer()

    def test_no_detections_returns_none_risk(self) -> None:
        result = self.scorer.score([])

        self.assertEqual(
            result,
            {
                "score": 0,
                "level": "NONE",
                "reasons": ["No sensitive data detected."],
            },
        )

    def test_one_low_risk_detection(self) -> None:
        result = self.scorer.score([
            make_detection("URL", 1.0),
        ])

        self.assertEqual(result["score"], 5)
        self.assertEqual(result["level"], "LOW")

    def test_one_medium_risk_detection(self) -> None:
        result = self.scorer.score([
            make_detection("EMAIL", 0.98),
        ])

        self.assertEqual(result["score"], 20)
        self.assertEqual(result["level"], "MEDIUM")

    def test_multiple_medium_detections_escalate_to_high(self) -> None:
        detections = [
            make_detection("PERSON", 0.90),
            make_detection("EMAIL", 0.90),
            make_detection("PHONE", 0.90),
        ]

        result = self.scorer.score(detections)

        self.assertEqual(result["score"], 57)
        self.assertEqual(result["level"], "HIGH")

    def test_high_risk_pii_has_high_floor(self) -> None:
        result = self.scorer.score([
            make_detection("NIC", 0.10),
        ])

        self.assertEqual(result["score"], 50)
        self.assertEqual(result["level"], "HIGH")

    def test_critical_credential_has_critical_floor(self) -> None:
        result = self.scorer.score([
            make_detection("API_KEY", 0.10),
        ])

        self.assertEqual(result["score"], 80)
        self.assertEqual(result["level"], "CRITICAL")

    def test_multiple_critical_secrets_reach_score_cap(self) -> None:
        detections = [
            make_detection("PASSWORD", 1.0),
            make_detection("API_KEY", 1.0),
            make_detection("TOKEN", 1.0),
        ]

        result = self.scorer.score(detections)

        self.assertEqual(result["score"], 100)
        self.assertEqual(result["level"], "CRITICAL")

    def test_confidence_influences_numeric_score(self) -> None:
        lower_confidence = self.scorer.score([
            make_detection("URL", 0.20),
        ])
        higher_confidence = self.scorer.score([
            make_detection("URL", 1.0),
        ])

        self.assertLess(
            lower_confidence["score"],
            higher_confidence["score"],
        )
        self.assertEqual(lower_confidence["level"], "LOW")
        self.assertEqual(higher_confidence["level"], "LOW")

    def test_additional_detection_increases_score(self) -> None:
        one_email = self.scorer.score([
            make_detection("EMAIL", 0.80),
        ])
        two_emails = self.scorer.score([
            make_detection("EMAIL", 0.80),
            make_detection("EMAIL", 0.80),
        ])

        self.assertGreater(two_emails["score"], one_email["score"])

    def test_score_is_capped_at_one_hundred(self) -> None:
        detections = [
            make_detection("JWT", 1.0)
            for _ in range(10)
        ]

        result = self.scorer.score(detections)

        self.assertEqual(result["score"], 100)

    def test_output_is_deterministic_for_input_order(self) -> None:
        detections = [
            make_detection("NIC", 0.90),
            make_detection("EMAIL", 0.80),
            make_detection("PERSON", 0.70),
        ]

        forward = self.scorer.score(detections)
        reversed_result = self.scorer.score(list(reversed(detections)))

        self.assertEqual(forward, reversed_result)

    def test_every_canonical_label_has_a_severity(self) -> None:
        self.assertEqual(set(LABEL_SEVERITY), set(CANONICAL_LABELS))

    def test_reasons_do_not_include_raw_sensitive_values(self) -> None:
        fictional_password = "FictionalPass123!"
        fictional_api_key = "demo_API_key_123456789"
        result = self.scorer.score([
            make_detection("PASSWORD", 0.99, fictional_password),
            make_detection("API_KEY", 0.99, fictional_api_key),
        ])
        rendered_result = str(result)

        self.assertNotIn(fictional_password, rendered_result)
        self.assertNotIn(fictional_api_key, rendered_result)

    def test_input_detections_are_not_modified(self) -> None:
        detections = [
            make_detection("EMAIL", 0.98, "kasun@example.com"),
        ]
        original = deepcopy(detections)

        self.scorer.score(detections)

        self.assertEqual(detections, original)

    def test_invalid_labels_and_scores_are_rejected(self) -> None:
        for invalid_label in ("person", "UNKNOWN_LABEL"):
            with self.subTest(invalid_label=invalid_label):
                with self.assertRaises(ValueError):
                    self.scorer.score([
                        make_detection(invalid_label, 0.90),
                    ])

        invalid_scores = (-0.01, 1.01, True, "0.90", float("nan"))

        for invalid_score in invalid_scores:
            with self.subTest(invalid_score=invalid_score):
                with self.assertRaises(ValueError):
                    self.scorer.score([
                        make_detection("EMAIL", invalid_score),  # type: ignore[arg-type]
                    ])


if __name__ == "__main__":
    unittest.main(verbosity=2)
