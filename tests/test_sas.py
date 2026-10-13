from __future__ import annotations

import hashlib
import os

import pytest

from model_setup import train_model
from sas.exceptions import SecurityError
from sas.ml_protection import secure_model_load
from sas.predeploy.container_verifier import verify_container_policy
from sas.predeploy.dependency_scanner import scan_requirements
from sas.predeploy.iam_policy import generate_least_privilege_policy
from sas.shield import reset_shield


@pytest.fixture(scope="session")
def model_path():
    path = train_model()
    os.environ["SAS_EXPECTED_MODEL_HASH"] = hashlib.sha256(path.read_bytes()).hexdigest()
    os.environ["SAS_MODEL_PATH"] = str(path)
    os.environ["SAS_EXTRACTION_THRESHOLD"] = "8"
    return path


@pytest.fixture
def handler(model_path):
    reset_shield()
    from functions.inference import handler as module

    module._model = None
    return module.inference_handler


def test_benign_inference(handler):
    res = handler({"client_id": "alice", "data": [[0.1, 0.2, -0.3, 0.0]]}, None)
    assert res["statusCode"] == 200
    assert len(res["prediction"]) == 1
    assert "proba" not in res


def test_malformed_rejected(handler):
    res = handler({"client_id": "bob", "data": "oops"}, None)
    assert res["statusCode"] == 400


def test_outlier_rejected(handler):
    res = handler({"client_id": "eve", "data": [[50.0, 50.0, 50.0, 50.0]]}, None)
    assert res["statusCode"] == 403


def test_extraction_pattern_throttled(handler):
    codes = []
    for i in range(12):
        res = handler({"client_id": "probe", "data": [[0.05 * i, 0.1, -0.2, 0.3]]}, None)
        codes.append(res["statusCode"])
    assert 429 in codes


def test_blocked_client_does_not_return_success(handler):
    codes = []
    for i in range(12):
        res = handler({"client_id": "persistent-probe", "data": [[0.05 * i, 0.1, -0.2, 0.3]]}, None)
        codes.append(res["statusCode"])
    assert 429 in codes
    assert codes[-1] == 403

    blocked = handler({"client_id": "persistent-probe", "data": [[0.1, 0.1, -0.2, 0.3]]}, None)
    assert blocked["statusCode"] == 403
    assert blocked["sas_action"] == "block"


def test_model_hash_mismatch(model_path):
    previous = os.environ["SAS_EXPECTED_MODEL_HASH"]
    os.environ["SAS_EXPECTED_MODEL_HASH"] = "ab" * 32
    reset_shield()
    try:
        with pytest.raises(SecurityError):
            secure_model_load(str(model_path), verify_signature=True)
    finally:
        os.environ["SAS_EXPECTED_MODEL_HASH"] = previous


def test_predeploy_controls(model_path):
    assert scan_requirements("requirements.txt") == []
    policy = generate_least_privilege_policy("functions/inference/handler.py")
    assert policy.aws["Statement"]
    report = verify_container_policy("deploy/Dockerfile", signature_present=True)
    assert report.allowed_base
    assert report.findings == []
