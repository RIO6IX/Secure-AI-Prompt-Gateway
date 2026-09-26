from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from detection_engine.models.entities import DetectionCandidate


@dataclass(frozen=True)
class DetectionContext:
    language: str
    original_text: str
    normalized_text: str
    index_map: list[int]
    # Detectors append notes about reduced coverage (e.g. NER size cap).
    warnings: list[str] = field(default_factory=list)


class BaseDetector(ABC):
    name: str

    @abstractmethod
    def detect(self, text: str, context: DetectionContext) -> list[DetectionCandidate]:
        """Return detection candidates without mutating text."""
