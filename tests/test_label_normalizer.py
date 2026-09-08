"""
Tests for LabelNormalizer.

Run from the project root with:

    python -m unittest tests.test_label_normalizer -v
"""

import unittest

from app.processing.label_normalizer import (
    CANONICAL_LABELS,
    LabelNormalizer,
    UnknownLabelError,
)


class LabelNormalizerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.normalizer = LabelNormalizer()

    def test_regex_aliases_are_normalized(self) -> None:
        expected_labels = {
            "SRI_LANKAN_PHONE": "PHONE",
            "SRI_LANKAN_OLD_NIC": "NIC",
            "SRI_LANKAN_NEW_NIC": "NIC",
            "SRI_LANKAN_PASSPORT": "PASSPORT",
        }

        for source_label, expected_label in expected_labels.items():
            with self.subTest(source_label=source_label):
                self.assertEqual(
                    self.normalizer.normalize_label(source_label),
                    expected_label,
                )

    def test_gliner_aliases_are_normalized(self) -> None:
        expected_labels = {
            "person": "PERSON",
            "person name": "PERSON",
            "organization": "ORGANIZATION",
            "job title": "JOB_TITLE",
            "address": "ADDRESS",
            "physical address": "ADDRESS",
            "city": "CITY",
            "province": "PROVINCE",
            "country": "COUNTRY",
            "date of birth": "DATE_OF_BIRTH",
            "bank": "BANK",
        }

        for source_label, expected_label in expected_labels.items():
            with self.subTest(source_label=source_label):
                self.assertEqual(
                    self.normalizer.normalize_label(source_label),
                    expected_label,
                )

    def test_canonical_labels_remain_unchanged(self) -> None:
        for label in CANONICAL_LABELS:
            with self.subTest(label=label):
                self.assertEqual(
                    self.normalizer.normalize_label(label),
                    label,
                )

    def test_detection_fields_and_values_are_preserved(self) -> None:
        original = {
            "label": "person",
            "text": "Kasun Perera",
            "start": 0,
            "end": 12,
            "score": 0.95,
            "source": "gliner",
        }

        result = self.normalizer.normalize([original])[0]

        self.assertEqual(result["label"], "PERSON")
        self.assertEqual(result["text"], original["text"])
        self.assertEqual(result["start"], original["start"])
        self.assertEqual(result["end"], original["end"])
        self.assertEqual(result["score"], original["score"])
        self.assertEqual(result["source"], original["source"])

    def test_input_detection_is_not_modified(self) -> None:
        original = {
            "label": "SRI_LANKAN_PHONE",
            "text": "+94 77 123 4567",
            "start": 10,
            "end": 25,
            "score": 0.95,
            "source": "regex",
        }

        normalized = self.normalizer.normalize([original])

        self.assertEqual(original["label"], "SRI_LANKAN_PHONE")
        self.assertIsNot(normalized[0], original)

    def test_empty_detection_list_returns_empty_list(self) -> None:
        self.assertEqual(self.normalizer.normalize([]), [])

    def test_unknown_label_is_reported(self) -> None:
        with self.assertRaises(UnknownLabelError):
            self.normalizer.normalize_label("fictional unknown label")

    def test_invalid_label_is_rejected(self) -> None:
        with self.assertRaises(TypeError):
            self.normalizer.normalize_label(None)  # type: ignore[arg-type]

        with self.assertRaises(ValueError):
            self.normalizer.normalize_label("   ")

    def test_invalid_detection_collection_is_rejected(self) -> None:
        with self.assertRaises(TypeError):
            self.normalizer.normalize({})  # type: ignore[arg-type]

        with self.assertRaises(TypeError):
            self.normalizer.normalize(["not a detection"])  # type: ignore[list-item]

        with self.assertRaises(ValueError):
            self.normalizer.normalize([{"text": "Kasun Perera"}])


if __name__ == "__main__":
    unittest.main(verbosity=2)
