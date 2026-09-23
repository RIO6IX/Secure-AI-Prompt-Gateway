"""Tunable risk-scoring policy (Component 02).

Organisations weigh risk differently: a bank may treat card data as
critical on its own, a software house may care most about source code and
cloud keys. The defaults live in risk_assessment.py; a JSON file named by
RISK_POLICY_FILE can override any part of them without code changes:

    {
      "entity_weights": {"CREDIT_CARD_NUMBER": 85, "SOURCE_CODE": 40},
      "category_defaults": {"FINANCIAL": 50},
      "thresholds": {"medium": 25, "high": 50, "critical": 80},
      "category_combination_bonus": 10,
      "repeat_attempt_points": 10,
      "repeat_attempt_cap": 30
    }

The file is validated strictly at startup: unknown keys, weights outside
0-100 or thresholds that are not increasing stop the service with a clear
message instead of silently mis-scoring prompts.
"""

from __future__ import annotations

import json
from pathlib import Path

from detection_engine.models.entities import Category
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

Weight = int


class Thresholds(BaseModel):
    model_config = ConfigDict(extra="forbid")

    medium: int = Field(default=25, ge=1, le=100)
    high: int = Field(default=50, ge=1, le=100)
    critical: int = Field(default=80, ge=1, le=100)

    @model_validator(mode="after")
    def increasing(self) -> Thresholds:
        if not self.medium < self.high < self.critical:
            raise ValueError("thresholds must satisfy medium < high < critical")
        return self


class RiskPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entity_weights: dict[str, Weight] = Field(default_factory=dict)
    category_defaults: dict[Category, Weight] = Field(default_factory=dict)
    thresholds: Thresholds = Field(default_factory=Thresholds)
    category_combination_bonus: int = Field(default=10, ge=0, le=50)
    repeat_attempt_points: int = Field(default=10, ge=0, le=50)
    repeat_attempt_cap: int = Field(default=30, ge=0, le=100)

    @field_validator("entity_weights", "category_defaults")
    @classmethod
    def weights_in_range(cls, weights: dict) -> dict:
        bad = {str(key): value for key, value in weights.items() if not 0 <= value <= 100}
        if bad:
            raise ValueError(f"weights must be between 0 and 100: {bad}")
        return weights

    def merged_with(self, base_weights: dict[str, int], base_categories: dict[Category, int]) -> RiskPolicy:
        """Defaults overlaid with this policy's overrides."""
        return self.model_copy(update={
            "entity_weights": {**base_weights, **self.entity_weights},
            "category_defaults": {**base_categories, **self.category_defaults},
        })


class RiskPolicyError(RuntimeError):
    pass


def load_risk_policy(path: str | None) -> RiskPolicy:
    """Read and validate a policy file; no path means built-in defaults."""
    if not path:
        return RiskPolicy()
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return RiskPolicy.model_validate(data)
    except FileNotFoundError as exc:
        raise RiskPolicyError(f"RISK_POLICY_FILE not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise RiskPolicyError(f"RISK_POLICY_FILE is not valid JSON ({path}): {exc}") from exc
    except ValidationError as exc:
        raise RiskPolicyError(f"RISK_POLICY_FILE is invalid ({path}):\n{exc}") from exc
