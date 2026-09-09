"""
Tests for ResultMerger.

Run from the project root with:

    python -m unittest tests.test_result_merger -v
"""

from copy import deepcopy
import unittest

from app.processing.result_merger import ResultMerger


def make_detection(
    label: str,
    text: str,
    start: int,
    score: float,
    source: str,
) -> dict:
    """Create one fictional detection with matching positions."""

    return {
        "label": label,
        "text": text,
        "start": start,
        "end": start + len(text),
        "score": score,
        "source": source,
    }


class ResultMergerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.merger = ResultMerger()

    def test_regex_email_removes_overlapping_gliner_person(self) -> None:
        regex_email = make_detection(
            "EMAIL",
            "kasun.perera@example.com",
            10,
            0.98,
            "regex",
        )
        gliner_person = make_detection(
            "PERSON",
            "kasun.perera",
            10,
            0.99,
            "gliner",
        )

        result = self.merger.merge([regex_email], [gliner_person])

        self.assertEqual(result, [regex_email])

    def test_regex_priority_ignores_higher_gliner_score(self) -> None:
        regex_result = make_detection(
            "EMAIL",
            "nadeesha@example.com",
            0,
            0.75,
            "regex",
        )
        gliner_result = make_detection(
            "PERSON",
            "nadeesha",
            0,
            0.99,
            "gliner",
        )

        result = self.merger.merge([regex_result], [gliner_result])

        self.assertEqual(result, [regex_result])

    def test_internal_url_removes_overlapping_gliner_ip(self) -> None:
        internal_url_text = "http://192.168.10.25/admin"
        regex_url = make_detection(
            "INTERNAL_URL",
            internal_url_text,
            20,
            0.99,
            "regex",
        )
        gliner_ip = make_detection(
            "IP_ADDRESS",
            "192.168.10.25",
            27,
            0.96,
            "gliner",
        )

        result = self.merger.merge([regex_url], [gliner_ip])

        self.assertEqual(result, [regex_url])

    def test_complete_name_is_preferred_over_split_names(self) -> None:
        full_name = make_detection(
            "PERSON",
            "Nadeesha Fernando",
            0,
            0.75,
            "gliner",
        )
        first_name = make_detection(
            "PERSON",
            "Nadeesha",
            0,
            0.98,
            "gliner",
        )
        last_name = make_detection(
            "PERSON",
            "Fernando",
            9,
            0.97,
            "gliner",
        )

        result = self.merger.merge(
            [],
            [first_name, last_name, full_name],
        )

        self.assertEqual(result, [full_name])

    def test_exact_duplicates_are_removed(self) -> None:
        regex_email = make_detection(
            "EMAIL",
            "kasun.perera@example.com",
            0,
            0.98,
            "regex",
        )
        gliner_city = make_detection(
            "CITY",
            "Kandy",
            30,
            0.90,
            "gliner",
        )

        result = self.merger.merge(
            [regex_email, regex_email.copy()],
            [gliner_city, gliner_city.copy()],
        )

        self.assertEqual(result, [regex_email, gliner_city])

    def test_same_span_different_labels_prefers_higher_score(self) -> None:
        person = make_detection(
            "PERSON",
            "ABC Systems",
            5,
            0.72,
            "gliner",
        )
        organization = make_detection(
            "ORGANIZATION",
            "ABC Systems",
            5,
            0.93,
            "gliner",
        )

        result = self.merger.merge([], [person, organization])

        self.assertEqual(result, [organization])

    def test_adjacent_detections_do_not_overlap(self) -> None:
        city = make_detection(
            "CITY",
            "Kandy",
            0,
            0.90,
            "gliner",
        )
        country = make_detection(
            "COUNTRY",
            "Sri Lanka",
            city["end"],
            0.91,
            "gliner",
        )

        result = self.merger.merge([], [country, city])

        self.assertEqual(result, [city, country])

    def test_results_are_sorted_by_start_position(self) -> None:
        later_regex = make_detection(
            "EMAIL",
            "kasun@example.com",
            30,
            0.98,
            "regex",
        )
        earlier_gliner = make_detection(
            "PERSON",
            "Kasun Perera",
            0,
            0.90,
            "gliner",
        )

        result = self.merger.merge([later_regex], [earlier_gliner])

        self.assertEqual(result, [earlier_gliner, later_regex])

    def test_inputs_are_not_modified_and_outputs_are_copies(self) -> None:
        regex_result = make_detection(
            "EMAIL",
            "kasun@example.com",
            0,
            0.98,
            "regex",
        )
        gliner_result = make_detection(
            "CITY",
            "Matara",
            30,
            0.90,
            "gliner",
        )
        regex_before = deepcopy([regex_result])
        gliner_before = deepcopy([gliner_result])

        result = self.merger.merge([regex_result], [gliner_result])

        self.assertEqual([regex_result], regex_before)
        self.assertEqual([gliner_result], gliner_before)
        self.assertIsNot(result[0], regex_result)
        self.assertIsNot(result[1], gliner_result)

    def test_empty_lists_return_empty_list(self) -> None:
        self.assertEqual(self.merger.merge([], []), [])

    def test_missing_required_field_is_rejected(self) -> None:
        incomplete_result = {
            "label": "EMAIL",
            "text": "kasun@example.com",
        }

        with self.assertRaises(ValueError):
            self.merger.merge([incomplete_result], [])

    def test_wrong_detector_source_is_rejected(self) -> None:
        wrong_source = make_detection(
            "PERSON",
            "Kasun Perera",
            0,
            0.90,
            "gliner",
        )

        with self.assertRaises(ValueError):
            self.merger.merge([wrong_source], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
