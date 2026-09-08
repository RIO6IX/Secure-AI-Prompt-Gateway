"""
Tests for PlaceholderSanitizer.

Run from the project root with:

    python -m unittest tests.test_sanitizer -v
"""

from copy import deepcopy
import unittest

from app.processing.sanitizer import PlaceholderSanitizer


def make_detection(
    prompt: str,
    label: str,
    value: str,
    occurrence: int = 0,
) -> dict:
    """Create a detection for one occurrence of a fictional value."""

    search_start = 0
    start = -1

    for _ in range(occurrence + 1):
        start = prompt.index(value, search_start)
        search_start = start + len(value)

    return {
        "label": label,
        "text": value,
        "start": start,
        "end": start + len(value),
    }


class PlaceholderSanitizerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sanitizer = PlaceholderSanitizer()

    def test_single_replacement(self) -> None:
        prompt = "Contact Kasun Perera."
        detection = make_detection(prompt, "PERSON", "Kasun Perera")

        result = self.sanitizer.sanitize(prompt, [detection])

        self.assertEqual(
            result["sanitized_text"],
            "Contact [PERSON_1].",
        )

    def test_multiple_different_labels_have_independent_numbers(self) -> None:
        prompt = "Kasun uses kasun@example.com."
        person = make_detection(prompt, "PERSON", "Kasun")
        email = make_detection(prompt, "EMAIL", "kasun@example.com")

        result = self.sanitizer.sanitize(prompt, [email, person])

        self.assertEqual(
            result["sanitized_text"],
            "[PERSON_1] uses [EMAIL_1].",
        )

    def test_multiple_values_of_same_label_are_numbered(self) -> None:
        prompt = "Kasun met Nadeesha."
        kasun = make_detection(prompt, "PERSON", "Kasun")
        nadeesha = make_detection(prompt, "PERSON", "Nadeesha")

        result = self.sanitizer.sanitize(prompt, [nadeesha, kasun])

        self.assertEqual(
            result["sanitized_text"],
            "[PERSON_1] met [PERSON_2].",
        )

    def test_repeated_identical_value_reuses_placeholder(self) -> None:
        prompt = "Kasun said Kasun approved it."
        first = make_detection(prompt, "PERSON", "Kasun", occurrence=0)
        second = make_detection(prompt, "PERSON", "Kasun", occurrence=1)

        result = self.sanitizer.sanitize(prompt, [second, first])

        self.assertEqual(
            result["sanitized_text"],
            "[PERSON_1] said [PERSON_1] approved it.",
        )
        self.assertEqual(
            [item["placeholder"] for item in result["replacements"]],
            ["[PERSON_1]", "[PERSON_1]"],
        )

    def test_adjacent_detections_are_replaced(self) -> None:
        prompt = "KasunNadeesha"
        kasun = make_detection(prompt, "PERSON", "Kasun")
        nadeesha = make_detection(prompt, "PERSON", "Nadeesha")

        result = self.sanitizer.sanitize(prompt, [nadeesha, kasun])

        self.assertEqual(
            result["sanitized_text"],
            "[PERSON_1][PERSON_2]",
        )

    def test_beginning_and_ending_positions(self) -> None:
        prompt = "kasun@example.com contacted Kasun"
        email = make_detection(prompt, "EMAIL", "kasun@example.com")
        person = make_detection(prompt, "PERSON", "Kasun")

        result = self.sanitizer.sanitize(prompt, [person, email])

        self.assertEqual(
            result["sanitized_text"],
            "[EMAIL_1] contacted [PERSON_1]",
        )

    def test_unicode_text_positions(self) -> None:
        fictional_name = "\u0db1\u0dd2\u0db8\u0dbd\u0dca"
        prompt = f"{fictional_name} lives in Kandy."
        person = make_detection(prompt, "PERSON", fictional_name)
        city = make_detection(prompt, "CITY", "Kandy")

        result = self.sanitizer.sanitize(prompt, [city, person])

        self.assertEqual(
            result["sanitized_text"],
            "[PERSON_1] lives in [CITY_1].",
        )

    def test_empty_detections_preserve_prompt(self) -> None:
        prompt = "Prepare a fictional general report."

        result = self.sanitizer.sanitize(prompt, [])

        self.assertEqual(result["sanitized_text"], prompt)
        self.assertEqual(result["replacements"], [])

    def test_original_prompt_and_detections_are_unchanged(self) -> None:
        prompt = "Kasun lives in Matara."
        detections = [
            make_detection(prompt, "PERSON", "Kasun"),
            make_detection(prompt, "CITY", "Matara"),
        ]
        prompt_before = prompt
        detections_before = deepcopy(detections)

        self.sanitizer.sanitize(prompt, detections)

        self.assertEqual(prompt, prompt_before)
        self.assertEqual(detections, detections_before)

    def test_detected_sensitive_values_do_not_remain(self) -> None:
        prompt = "Kasun uses kasun@example.com."
        sensitive_values = ["Kasun", "kasun@example.com"]
        detections = [
            make_detection(prompt, "PERSON", sensitive_values[0]),
            make_detection(prompt, "EMAIL", sensitive_values[1]),
        ]

        sanitized_text = self.sanitizer.sanitize(
            prompt,
            detections,
        )["sanitized_text"]

        for value in sensitive_values:
            self.assertNotIn(value, sanitized_text)

    def test_replacement_metadata_has_no_raw_text(self) -> None:
        prompt = "Kasun lives in Kandy."
        detections = [
            make_detection(prompt, "PERSON", "Kasun"),
            make_detection(prompt, "CITY", "Kandy"),
        ]

        replacements = self.sanitizer.sanitize(
            prompt,
            detections,
        )["replacements"]

        for replacement in replacements:
            self.assertEqual(
                set(replacement),
                {"label", "placeholder", "start", "end"},
            )
            self.assertNotIn("Kasun", replacement.values())
            self.assertNotIn("Kandy", replacement.values())

    def test_replacement_metadata_uses_original_positions(self) -> None:
        prompt = "Email kasun@example.com now."
        email = make_detection(prompt, "EMAIL", "kasun@example.com")

        replacement = self.sanitizer.sanitize(
            prompt,
            [email],
        )["replacements"][0]

        self.assertEqual(replacement["start"], email["start"])
        self.assertEqual(replacement["end"], email["end"])

    def test_overlapping_detections_are_rejected(self) -> None:
        prompt = "kasun@example.com"
        email = make_detection(prompt, "EMAIL", prompt)
        person = make_detection(prompt, "PERSON", "kasun")

        with self.assertRaises(ValueError):
            self.sanitizer.sanitize(prompt, [email, person])

    def test_mismatched_text_and_positions_are_rejected(self) -> None:
        prompt = "Kasun"
        mismatched = {
            "label": "PERSON",
            "text": "KasunX",
            "start": 0,
            "end": 5,
        }

        with self.assertRaises(ValueError):
            self.sanitizer.sanitize(prompt, [mismatched])

    def test_unnormalized_label_is_rejected(self) -> None:
        prompt = "Kasun"
        detection = make_detection(prompt, "person", "Kasun")

        with self.assertRaises(ValueError):
            self.sanitizer.sanitize(prompt, [detection])


if __name__ == "__main__":
    unittest.main(verbosity=2)
