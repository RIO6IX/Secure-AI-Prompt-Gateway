"""
Tests for the RegexDetector.

Run from the project root with:

    python -m tests.test_regex_detector
"""

from app.detectors.regex_detector import RegexDetector
from tests.fictional_test_data import (
    EXPECTED_EXAMPLES,
    EXPECTED_LABELS,
    FICTIONAL_TEST_PROMPT,
    SHOULD_NOT_BE_DETECTED,
)


def print_detection_results(results: list[dict]) -> None:
    print("\nDetected sensitive values:\n")

    for result in results:
        print(
            f"Label: {result['label']}\n"
            f"Text: {result['text']}\n"
            f"Score: {result['score']:.2f}\n"
            f"Position: {result['start']} - {result['end']}\n"
            f"Source: {result['source']}\n"
            + "-" * 50
        )


def test_required_fields(results: list[dict]) -> None:
    required_fields = {
        "label",
        "text",
        "start",
        "end",
        "score",
        "source",
    }

    for result in results:
        missing_fields = required_fields - result.keys()

        assert not missing_fields, (
            f"Missing fields {missing_fields} in result: {result}"
        )


def test_positions(results: list[dict]) -> None:
    for result in results:
        start = result["start"]
        end = result["end"]
        matched_text = result["text"]

        assert start >= 0, f"Invalid start position: {result}"
        assert end > start, f"Invalid end position: {result}"

        extracted_text = FICTIONAL_TEST_PROMPT[start:end]

        assert extracted_text == matched_text, (
            f"Position mismatch for {result['label']}:\n"
            f"Expected text: {matched_text}\n"
            f"Extracted text: {extracted_text}"
        )


def test_confidence_scores(results: list[dict]) -> None:
    for result in results:
        score = result["score"]

        assert isinstance(score, float), (
            f"Score must be a float: {result}"
        )

        assert 0.0 <= score <= 1.0, (
            f"Score must be between 0 and 1: {result}"
        )


def test_duplicate_results(results: list[dict]) -> None:
    seen = set()

    for result in results:
        key = (
            result["label"],
            result["start"],
            result["end"],
            result["text"],
        )

        assert key not in seen, f"Duplicate result found: {result}"
        seen.add(key)


def test_overlapping_results(results: list[dict]) -> None:
    sorted_results = sorted(
        results,
        key=lambda item: item["start"],
    )

    for index, current in enumerate(sorted_results):
        for next_result in sorted_results[index + 1:]:
            if next_result["start"] >= current["end"]:
                break

            overlaps = (
                current["start"] < next_result["end"]
                and current["end"] > next_result["start"]
            )

            assert not overlaps, (
                "Overlapping detections found:\n"
                f"{current}\n"
                f"{next_result}"
            )


def test_expected_labels(results: list[dict]) -> None:
    detected_labels = {
        result["label"]
        for result in results
    }

    missing_labels = EXPECTED_LABELS - detected_labels

    if missing_labels:
        print("\nMissing expected labels:")
        for label in sorted(missing_labels):
            print(f"  - {label}")

    assert not missing_labels, (
        f"Missing expected labels: {sorted(missing_labels)}"
    )


def test_expected_examples(results: list[dict]) -> None:
    detected_pairs = {
        (result["label"], result["text"])
        for result in results
    }

    missing_examples = []

    for label, expected_values in EXPECTED_EXAMPLES.items():
        for expected_value in expected_values:
            if (label, expected_value) not in detected_pairs:
                missing_examples.append(
                    (label, expected_value)
                )

    if missing_examples:
        print("\nMissing expected examples:")

        for label, value in missing_examples:
            print(f"  - {label}: {value}")

    assert not missing_examples, (
        f"Missing expected examples: {missing_examples}"
    )


def test_false_positives(results: list[dict]) -> None:
    detected_texts = {
        result["text"]
        for result in results
    }

    false_positives = [
        value
        for value in SHOULD_NOT_BE_DETECTED
        if value in detected_texts
    ]

    if false_positives:
        print("\nUnexpected false positives:")

        for value in false_positives:
            print(f"  - {value}")

    assert not false_positives, (
        f"False-positive values detected: {false_positives}"
    )


def run_tests() -> None:
    detector = RegexDetector()
    results = detector.detect(FICTIONAL_TEST_PROMPT)

    print_detection_results(results)

    tests = [
        ("Required fields", test_required_fields),
        ("Start and end positions", test_positions),
        ("Confidence scores", test_confidence_scores),
        ("Duplicate removal", test_duplicate_results),
        ("Overlap removal", test_overlapping_results),
        ("Expected labels", test_expected_labels),
        ("Expected values", test_expected_examples),
        ("False-positive checks", test_false_positives),
    ]

    passed = 0
    failed = 0

    print("\nTest summary:\n")

    for test_name, test_function in tests:
        try:
            test_function(results)
            print(f"[PASS] {test_name}")
            passed += 1

        except AssertionError as error:
            print(f"[FAIL] {test_name}")
            print(f"       {error}")
            failed += 1

    print("\n" + "=" * 50)
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Total detections: {len(results)}")
    print("=" * 50)

    if failed > 0:
        raise SystemExit(1)


if __name__ == "__main__":
    run_tests()
