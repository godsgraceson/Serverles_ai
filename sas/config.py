from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return default if raw is None else int(raw)


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    return default if raw is None else float(raw)


@dataclass
class SASConfig:
    """Runtime knobs matching paper Section V.B protection mechanisms."""

    project_root: Path = field(default_factory=lambda: Path(__file__).resolve().parents[1])
    expected_model_hash: str | None = field(
        default_factory=lambda: os.environ.get("SAS_EXPECTED_MODEL_HASH")
    )
    trusted_model_sources: tuple[str, ...] = ("local-signed", "sklearn-trained")
    extraction_query_window: int = field(
        default_factory=lambda: _env_int("SAS_EXTRACTION_WINDOW", 60)
    )
    extraction_query_threshold: int = field(
        default_factory=lambda: _env_int("SAS_EXTRACTION_THRESHOLD", 40)
    )
    rate_limit_per_minute: int = field(
        default_factory=lambda: _env_int("SAS_RATE_LIMIT", 120)
    )
    adversarial_zscore: float = field(
        default_factory=lambda: _env_float("SAS_ADV_ZSCORE", 4.0)
    )
    return_confidence_scores: bool = field(
        default_factory=lambda: _env_bool("SAS_RETURN_CONFIDENCE", False)
    )
    forensic_log_path: Path = field(
        default_factory=lambda: Path(
            os.environ.get("SAS_FORENSIC_LOG", "logs/sas_forensics.jsonl")
        )
    )
    tmp_dir: Path = field(default_factory=lambda: Path(os.environ.get("SAS_TMP_DIR", "/tmp")))
    baseline_feature_mean: float = 0.0
    baseline_feature_std: float = 1.0
    cold_start_ratio_alert: float = 6.0


def load_config() -> SASConfig:
    return SASConfig()
