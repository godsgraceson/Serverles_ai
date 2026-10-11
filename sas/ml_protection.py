from __future__ import annotations

import logging
from pathlib import Path

import joblib

from sas.config import load_config
from sas.exceptions import SecurityError
from sas.predeploy.model_integrity import ModelRegistry

logger = logging.getLogger("SAS-Protection")


def secure_model_load(model_path: str, verify_signature: bool = True, source: str = "local-signed"):
    """Load an ML artifact only after hash + registry provenance checks."""
    path = Path(model_path)
    if verify_signature:
        logger.info("Verifying cryptographic integrity for %s", path)
        registry = ModelRegistry()
        registry.verify(path)
    if not path.exists():
        raise SecurityError(f"Model file not found at {path}")
    return joblib.load(path)


def sign_and_export_hash(model_path: str, source: str = "sklearn-trained") -> str:
    registry = ModelRegistry()
    manifest = registry.sign(model_path, source=source)
    load_config()
    return manifest.sha256
