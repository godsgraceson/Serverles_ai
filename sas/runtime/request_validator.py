from __future__ import annotations

import math
from dataclasses import dataclass

from sas.config import SASConfig, load_config
from sas.runtime.invocation_analyzer import _flatten


@dataclass
class ValidationResult:
    ok: bool
    status_code: int
    message: str
    flags: list[str]


class RequestValidator:
    """Input sanitization, statistical outlier checks, extraction-query shape checks."""

    def __init__(self, n_features: int = 4, config: SASConfig | None = None) -> None:
        self.n_features = n_features
        self.config = config or load_config()

    def validate(self, event: dict) -> ValidationResult:
        flags: list[str] = []
        if not isinstance(event, dict):
            return ValidationResult(False, 400, "event must be an object", ["malformed"])
        data = event.get("data")
        if not isinstance(data, list) or not data:
            return ValidationResult(False, 400, "payload 'data' must be a non-empty list of feature rows", ["malformed"])
        rows = data if isinstance(data[0], list) else [data]
        for row in rows:
            if not isinstance(row, list) or len(row) != self.n_features:
                return ValidationResult(
                    False, 400, f"each row must have {self.n_features} numeric features", ["malformed"]
                )
            if not all(isinstance(x, (int, float)) and math.isfinite(float(x)) for x in row):
                return ValidationResult(False, 400, "features must be finite numbers", ["malformed"])

        values = _flatten(rows)
        if values:
            mean = self.config.baseline_feature_mean
            std = max(self.config.baseline_feature_std, 1e-6)
            z_max = max(abs(v - mean) / std for v in values)
            l2 = math.sqrt(sum(v * v for v in values))
            if z_max >= self.config.adversarial_zscore or l2 >= self.config.adversarial_zscore * math.sqrt(len(values)):
                flags.append("statistical_outlier")
                return ValidationResult(
                    False,
                    403,
                    "input rejected by statistical adversarial filter",
                    flags,
                )
        return ValidationResult(True, 200, "ok", flags)
