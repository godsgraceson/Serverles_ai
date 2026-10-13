#!/usr/bin/env python3
"""Safe local attack emulation for the SAS thesis demo.

This script does not exploit cloud platforms, install malicious packages, or
generate reusable offensive payloads. It maps the paper's attack categories to
controlled local signals that the Serverless AI Shield can detect and explain.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from model_setup import train_model
from sas.exceptions import SecurityError
from sas.ml_protection import secure_model_load
from sas.predeploy.container_verifier import verify_container_policy
from sas.predeploy.dependency_scanner import scan_requirements
from sas.predeploy.iam_policy import generate_least_privilege_policy
from sas.shield import reset_shield


def _fresh_handler():
    reset_shield()
    from functions.inference import handler as h

    h._model = None
    return h.inference_handler


def _scenario(results: dict, name: str, passed: bool, evidence: dict) -> None:
    row = {"name": name, "passed": passed, "evidence": evidence}
    results["scenarios"].append(row)
    (results["passed"] if passed else results["failed"]).append(name)
    print(f"[{'PASS' if passed else 'FAIL'}] {name}: {evidence}")


def run_emulation() -> dict:
    model_path = train_model()
    good_hash = hashlib.sha256(model_path.read_bytes()).hexdigest()
    os.environ["SAS_EXPECTED_MODEL_HASH"] = good_hash
    os.environ["SAS_MODEL_PATH"] = str(model_path)
    os.environ["SAS_EXTRACTION_THRESHOLD"] = "8"
    os.environ["SAS_RATE_LIMIT"] = "50"

    results = {
        "scope": (
            "Safe local attack emulation. These scenarios generate defensive "
            "signals only; they are not real exploit generators."
        ),
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "scenarios": [],
        "passed": [],
        "failed": [],
    }

    handler = _fresh_handler()

    benign = handler({"client_id": "emu-benign", "data": [[0.2, -0.1, 0.4, 0.0]]}, None)
    _scenario(
        results,
        "benign request still succeeds",
        benign.get("statusCode") == 200 and "prediction" in benign,
        {"status": benign.get("statusCode"), "prediction": benign.get("prediction")},
    )
    _scenario(
        results,
        "confidence output is stripped",
        "proba" not in benign and "confidence" not in benign,
        {"returned_keys": sorted(benign.keys())},
    )

    malformed = handler({"client_id": "emu-malformed", "data": "not-a-matrix"}, None)
    _scenario(
        results,
        "malformed payload blocked",
        malformed.get("statusCode") == 400,
        {"status": malformed.get("statusCode"), "action": malformed.get("sas_action")},
    )

    outlier = handler({"client_id": "emu-outlier", "data": [[999.0, 999.0, 999.0, 999.0]]}, None)
    _scenario(
        results,
        "outlier input blocked",
        outlier.get("statusCode") == 403,
        {"status": outlier.get("statusCode"), "action": outlier.get("sas_action")},
    )

    query_codes: list[int] = []
    for i in range(12):
        res = handler({"client_id": "emu-extract", "data": [[i * 0.11, 0.2, -0.3, 0.05 * i]]}, None)
        query_codes.append(int(res.get("statusCode", 0)))
    _scenario(
        results,
        "model-extraction style query volume throttled",
        429 in query_codes,
        {"status_sequence": query_codes},
    )

    os.environ["SAS_EXTRACTION_THRESHOLD"] = "100"
    burst_handler = _fresh_handler()
    burst_codes: list[int] = []
    for i in range(16):
        res = burst_handler({"client_id": "emu-burst", "data": [[0.1, 0.1, -0.2, 0.3]]}, None)
        burst_codes.append(int(res.get("statusCode", 0)))
    _scenario(
        results,
        "burst invocation throttled",
        429 in burst_codes,
        {"status_sequence": burst_codes},
    )

    previous_hash = os.environ.get("SAS_EXPECTED_MODEL_HASH")
    os.environ["SAS_EXPECTED_MODEL_HASH"] = "0" * 64
    reset_shield()
    try:
        secure_model_load(str(model_path), verify_signature=True)
        tamper_blocked = False
    except SecurityError:
        tamper_blocked = True
    finally:
        os.environ["SAS_EXPECTED_MODEL_HASH"] = previous_hash or good_hash
    _scenario(
        results,
        "model artifact tampering rejected",
        tamper_blocked,
        {"expected_hash_replaced_with": "0" * 64},
    )

    with tempfile.TemporaryDirectory(prefix="sas_emulation_") as tmp:
        tmpdir = Path(tmp)

        fake_requirements = tmpdir / "requirements.txt"
        fake_requirements.write_text("mlflow==2.0.0\nscikit-learn==1.3.0\n", encoding="utf-8")
        dep_findings = scan_requirements(fake_requirements)
        _scenario(
            results,
            "dependency-poisoning risk flagged",
            any(f.package == "mlflow" for f in dep_findings),
            {"findings": [f.__dict__ for f in dep_findings]},
        )

        fake_dockerfile = tmpdir / "Dockerfile"
        fake_dockerfile.write_text("FROM unknown/ml-runtime:latest\nUSER root\n", encoding="utf-8")
        image_report = verify_container_policy(fake_dockerfile, signature_present=False)
        _scenario(
            results,
            "container supply-chain risk flagged",
            bool(image_report.findings),
            image_report.__dict__,
        )

        fake_handler = tmpdir / "handler.py"
        fake_handler.write_text(
            "import subprocess\n"
            "def handler(event, context):\n"
            "    subprocess.Popen(['echo', 'blocked-demo'])\n",
            encoding="utf-8",
        )
        policy = generate_least_privilege_policy(fake_handler)
        _scenario(
            results,
            "dangerous runtime primitive detected by static analysis",
            bool(policy.findings),
            {"findings": policy.findings, "aws_actions": policy.aws["Statement"][0]["Action"]},
        )

    report_path = ROOT / "artifacts" / "attack_emulation_report.json"
    results["report_path"] = str(report_path)
    results["detection_proxy"] = round(
        len(results["passed"]) / max(len(results["passed"]) + len(results["failed"]), 1), 3
    )
    report_path.parent.mkdir(exist_ok=True)
    report_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    return results


if __name__ == "__main__":
    summary = run_emulation()
    print(json.dumps(summary, indent=2))
    if summary["failed"]:
        raise SystemExit(1)
