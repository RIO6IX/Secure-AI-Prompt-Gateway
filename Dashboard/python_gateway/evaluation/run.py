"""Precision/recall benchmark for the Sensitive Data Detection Engine.

Usage (from Dashboard/python_gateway):

    python -m evaluation.run            # print the report
    python -m evaluation.run --markdown # print it as a Markdown table

A predicted entity is a true positive when its type equals the label and
its span overlaps the labelled value. Everything else in scope is a false
positive, and every unmatched label is a false negative.
"""

from __future__ import annotations

import argparse
import statistics
import time
from collections import defaultdict
from dataclasses import dataclass, field

from detection_engine.engine.detection_engine import SensitiveDataDetectionEngine
from detection_engine.models.request import DetectRequest
from evaluation.dataset import CASES, IGNORED_TYPES, Case


@dataclass
class Counts:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0


@dataclass
class Report:
    per_type: dict[str, Counts] = field(default_factory=lambda: defaultdict(Counts))
    errors: list[str] = field(default_factory=list)
    latencies_ms: list[float] = field(default_factory=list)

    @property
    def total(self) -> Counts:
        total = Counts()
        for counts in self.per_type.values():
            total.tp += counts.tp
            total.fp += counts.fp
            total.fn += counts.fn
        return total


def label_spans(case: Case) -> list[tuple[str, int, int]]:
    spans = []
    for entity_type, value in case.labels:
        start = case.prompt.index(value)
        spans.append((entity_type, start, start + len(value)))
    return spans


def evaluate(engine: SensitiveDataDetectionEngine | None = None) -> Report:
    engine = engine or SensitiveDataDetectionEngine()
    report = Report()
    for case in CASES:
        started = time.perf_counter()
        result = engine.detect(DetectRequest(prompt=case.prompt))
        report.latencies_ms.append((time.perf_counter() - started) * 1000)

        expected = label_spans(case)
        matched: set[int] = set()
        for entity in result.detected_entities:
            if entity.entity_type in IGNORED_TYPES:
                continue
            hit = next(
                (
                    index for index, (entity_type, start, end) in enumerate(expected)
                    if index not in matched and entity_type == entity.entity_type
                    and entity.start < end and start < entity.end
                ),
                None,
            )
            if hit is None:
                report.per_type[entity.entity_type].fp += 1
                report.errors.append(f"FP {entity.entity_type:26} {case.prompt[entity.start:entity.end]!r}")
            else:
                matched.add(hit)
                report.per_type[entity.entity_type].tp += 1
        for index, (entity_type, start, end) in enumerate(expected):
            if index not in matched:
                report.per_type[entity_type].fn += 1
                report.errors.append(f"FN {entity_type:26} {case.prompt[start:end]!r}")
    return report


def render(report: Report, markdown: bool) -> str:
    rows = sorted(report.per_type.items())
    total = report.total
    latencies = sorted(report.latencies_ms)
    p95 = latencies[max(0, round(0.95 * len(latencies)) - 1)]
    lines = []
    if markdown:
        lines += ["| Entity type | TP | FP | FN | Precision | Recall | F1 |", "|---|---:|---:|---:|---:|---:|---:|"]
        for name, c in rows:
            lines.append(f"| {name} | {c.tp} | {c.fp} | {c.fn} | {c.precision:.2f} | {c.recall:.2f} | {c.f1:.2f} |")
        lines.append(f"| **Overall** | {total.tp} | {total.fp} | {total.fn} | **{total.precision:.3f}** | **{total.recall:.3f}** | **{total.f1:.3f}** |")
    else:
        lines.append(f"{'entity type':28} {'tp':>3} {'fp':>3} {'fn':>3} {'prec':>6} {'rec':>6} {'f1':>6}")
        for name, c in rows:
            lines.append(f"{name:28} {c.tp:3} {c.fp:3} {c.fn:3} {c.precision:6.2f} {c.recall:6.2f} {c.f1:6.2f}")
        lines.append(f"{'OVERALL':28} {total.tp:3} {total.fp:3} {total.fn:3} {total.precision:6.3f} {total.recall:6.3f} {total.f1:6.3f}")
    lines.append("")
    lines.append(
        f"{len(CASES)} prompts ({sum(1 for case in CASES if not case.labels)} hard negatives); "
        f"latency median {statistics.median(latencies):.1f} ms, p95 {p95:.1f} ms"
    )
    if report.errors:
        lines.append("")
        lines += report.errors
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--markdown", action="store_true", help="print a Markdown table")
    args = parser.parse_args()
    print(render(evaluate(), args.markdown))


if __name__ == "__main__":
    main()
