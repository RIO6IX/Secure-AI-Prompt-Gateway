from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from detection_engine.models.entities import DetectionCandidate


@dataclass(frozen=True)
class DetectionContext:
    language: str
    original_text: str
    normalized_text: str
    index_map: list[int]


class BaseDetector(ABC):
    name: str

    @abstractmethod
    def detect(self, text: str, context: DetectionContext) -> list[DetectionCandidate]:
        """Return detection candidates without mutating text."""
