from __future__ import annotations

import re

from detection_engine.detectors.base import BaseDetector, DetectionContext
from detection_engine.models.entities import Category, DetectionCandidate, DetectionMethod, RiskLevel

CODE_KEYWORDS = re.compile(r"\b(def|class|function|const|let|var|import|from|public|private|SELECT|INSERT|UPDATE|CREATE TABLE|resource|provider|docker|ENV)\b")
CONFIDENTIAL_RE = re.compile(r"(?i)\b(confidential|proprietary|internal|production|trade secret|do not share)\b")
ENV_RE = re.compile(r"(?m)^[A-Z][A-Z0-9_]{2,40}\s*=\s*.+$")


class SourceCodeDetector(BaseDetector):
    name = "source_code_detector"

    def detect(self, text: str, context: DetectionContext) -> list[DetectionCandidate]:
        lines = text.splitlines()
        if not lines:
            return []
        code_like = 0
        language = "unknown"
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            if CODE_KEYWORDS.search(stripped) or ENV_RE.search(stripped) or stripped.endswith((";", "{", "}")):
                code_like += 1
            if stripped.startswith(("def ", "import ", "from ")):
                language = "python"
            elif "function " in stripped or stripped.startswith(("const ", "let ", "var ")):
                language = "javascript"
            elif stripped.upper().startswith(("SELECT ", "CREATE TABLE", "INSERT ")):
                language = "sql"
        symbol_count = sum(text.count(symbol) for symbol in "{}();=<>")
        symbol_density = symbol_count / max(1, len(text))
        confidentiality = bool(CONFIDENTIAL_RE.search(text))
        score = min(1.0, (code_like / max(3, len(lines))) + symbol_density * 4 + (0.25 if confidentiality else 0.0))
        if code_like < 2 and score < 0.45:
            return []
        confidence = max(0.42, min(0.82, score))
        return [DetectionCandidate(
            entity_type="PRIVATE_SOURCE_CODE" if confidentiality else "SOURCE_CODE",
            category=Category.SOURCE_CODE,
            start=0,
            end=len(text),
            value=text[:256],
            confidence=confidence,
            risk_level=RiskLevel.HIGH if confidentiality else RiskLevel.MEDIUM,
            detection_methods=[DetectionMethod.SOURCE_CODE_HEURISTIC],
            rule_name="source_code_heuristic",
            language_guess=language,
            metadata={"code_like_lines": code_like, "code_likeness_score": round(score, 3), "confidentiality_keyword": confidentiality},
        )]
