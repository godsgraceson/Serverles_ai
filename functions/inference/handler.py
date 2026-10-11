from __future__ import annotations

import os
from pathlib import Path

import numpy as np

from sas.adapters.normalize import normalize_event
from sas.middleware import secure_function
from sas.ml_protection import secure_model_load

ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = Path(os.environ.get("SAS_MODEL_PATH", ROOT / "artifacts" / "model.pkl"))

_model = None


def _model_instance():
    global _model
    if _model is None:
        _model = secure_model_load(str(MODEL_PATH), verify_signature=True)
    return _model


@secure_function(
    validate_input=True,
    memory_isolation=True,
    execution_monitoring=True,
    model_extraction_protection=True,
    n_features=4,
)
def inference_handler(event, context=None):
    canonical = normalize_event(event)
    features = canonical["data"]
    rows = np.array(features if isinstance(features[0], list) else [features], dtype=float)
    model = _model_instance()
    prediction = model.predict(rows)
    result = {"statusCode": 200, "prediction": prediction.tolist()}
    if hasattr(model, "predict_proba"):
        result["proba"] = model.predict_proba(rows).tolist()
    return result


def lambda_handler(event, context=None):
    return inference_handler(event, context)


def azure_http_handler(req) -> dict:
    payload = req.get_json() if hasattr(req, "get_json") else req
    return inference_handler(payload, None)


def gcp_http_handler(request):
    payload = request.get_json(silent=True) if hasattr(request, "get_json") else request
    return inference_handler(payload, None)
