"""Regression gate: the detection engine must keep its benchmark scores."""

from evaluation.dataset import CASES
from evaluation.run import evaluate


def test_benchmark_precision_and_recall_do_not_regress() -> None:
    report = evaluate()
    total = report.total

    assert total.recall >= 0.95, "\n".join(report.errors)
    assert total.precision >= 0.95, "\n".join(report.errors)


def test_benchmark_labels_are_present_in_their_prompts() -> None:
    for case in CASES:
        for _, value in case.labels:
            assert value in case.prompt
