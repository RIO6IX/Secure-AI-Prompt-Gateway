"""Prometheus metrics for Component 02 (sanitization, risk, reply guard).

Exposed on /metrics next to the detection engine's metrics, e.g.

    prompt_decisions_total{decision="BLOCK",source="browser-extension"} 12
    prompt_replacements_total{entity_type="EMAIL_ADDRESS"} 40
    prompt_risk_score_bucket{le="50.0"} 31
    reply_values_masked_total{kind="generated"} 3
    conversations_active 5

Labels only carry bounded values (decision, source channel, entity type),
never prompt content.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest

KNOWN_SOURCES = {"secure-chat-gateway", "browser-extension", "dashboard-prompt-monitor", "python-gateway"}


class SanitizerMetrics:
    def __init__(self, active_conversations: Callable[[], int] = lambda: 0) -> None:
        self.registry = CollectorRegistry()
        self.decisions = Counter(
            "prompt_decisions_total", "Prompt decisions by outcome and channel",
            ["decision", "source"], registry=self.registry,
        )
        self.replacements = Counter(
            "prompt_replacements_total", "Values replaced with placeholders, by entity type",
            ["entity_type"], registry=self.registry,
        )
        self.risk_score = Histogram(
            "prompt_risk_score", "Component 02 risk score per prompt",
            buckets=(0, 10, 25, 50, 80, 100), registry=self.registry,
        )
        self.reply_masked = Counter(
            "reply_values_masked_total", "Values masked in model replies (placeholder = echoed, generated = produced by the model)",
            ["kind"], registry=self.registry,
        )
        self.conversations = Gauge("conversations_active", "Open chat conversations", registry=self.registry)
        self.conversations.set_function(active_conversations)

    def record_prompt(self, decision: str, source: str, score: int, entity_types: Iterable[str]) -> None:
        # Unknown client-supplied sources are grouped to keep label cardinality bounded.
        channel = source if source in KNOWN_SOURCES else "other"
        self.decisions.labels(decision=decision, source=channel).inc()
        self.risk_score.observe(score)
        for entity_type in entity_types:
            self.replacements.labels(entity_type=entity_type).inc()

    def record_reply(self, placeholders_masked: int, findings_masked: int) -> None:
        if placeholders_masked:
            self.reply_masked.labels(kind="placeholder").inc(placeholders_masked)
        if findings_masked:
            self.reply_masked.labels(kind="generated").inc(findings_masked)

    def render(self) -> str:
        return generate_latest(self.registry).decode("utf-8")
