#!/usr/bin/env python3
"""Defensive evaluation of SAS controls (paper Section VI metrics, local).

Sends labeled benign and policy-violating *request patterns* through the
protected handler. It does not implement attack algorithms, payloads, or
platform exploits.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from model_setup import train_model
from sas.exceptions import SecurityError
from sas.ml_protection import secure_model_load
from sas.predeploy.dependency_scanner import scan_requirements
from sas.predeploy.iam_policy import generate_least_privilege_policy
from sas.shield import reset_shield


def _fresh_handler():
    reset_shield()
    from functions.inference import handler as h

    h._model = None
    return h.inference_handler


def evaluate() -> dict:
    model_path = train_model()
    os.environ["SAS_EXPECTED_MODEL_HASH"] = hashlib.sha256(model_path.read_bytes()).hexdigest()
    os.environ["SAS_MODEL_PATH"] = str(model_path)
    os.environ["SAS_EXTRACTION_THRESHOLD"] = "8"
    os.environ["SAS_RATE_LIMIT"] = "50"
    reset_shield()

    results = {
        "paper_scope": (
            "Defensive SAS control evaluation. These are labeled request "
            "patterns and tamper checks, not live exploit generators."
        ),
        "scenarios": [],
        "passed": [],
        "failed": [],
    }

    def expect(name: str, ok: bool) -> None:
        (results["passed"] if ok else results["failed"]).append(name)
        results["scenarios"].append({"name": name, "passed": ok})
        print(f"[{'PASS' if ok else 'FAIL'}] {name}")

    handler = _fresh_handler()

    t0 = time.perf_counter()
    clean = handler({"client_id": "user-a", "data": [[0.2, -0.1, 0.4, 0.0]]}, None)
    latency = time.perf_counter() - t0
    expect("benign inference", clean.get("statusCode") == 200 and "prediction" in clean)
    expect("confidence scores stripped", "proba" not in clean)

    bad = handler({"client_id": "user-b", "data": "not-a-matrix"}, None)
    expect("malformed input blocked", bad.get("statusCode") == 400)

    outlier = handler({"client_id": "user-c", "data": [[999.0, 999.0, 999.0, 999.0]]}, None)
    expect("statistical outlier blocked", outlier.get("statusCode") == 403)

    blocked = 0
    for i in range(12):
        res = handler({"client_id": "extract-sim", "data": [[i * 0.11, 0.2, -0.3, 0.05 * i]]}, None)
        if res.get("statusCode") == 429:
            blocked += 1
    expect("extraction-like query volume throttled", blocked >= 1)

    tampered_env = os.environ.get("SAS_EXPECTED_MODEL_HASH")
    os.environ["SAS_EXPECTED_MODEL_HASH"] = "0" * 64
    reset_shield()
    try:
        secure_model_load(str(model_path), verify_signature=True)
        expect("tampered hash rejected", False)
    except SecurityError:
        expect("tampered hash rejected", True)
    os.environ["SAS_EXPECTED_MODEL_HASH"] = tampered_env or ""

    dep_findings = scan_requirements(ROOT / "requirements.txt")
    expect("dependency scan completed", isinstance(dep_findings, list))
    policy = generate_least_privilege_policy(ROOT / "functions" / "inference" / "handler.py")
    expect("iam policy generated", "Statement" in policy.aws)

    results["inference_latency_s"] = round(latency, 6)
    results["detection_proxy"] = round(
        len(results["passed"]) / max(len(results["passed"]) + len(results["failed"]), 1), 3
    )
    report_path = ROOT / "artifacts" / "evaluation_report.json"
    results["evaluated_at"] = datetime.now(timezone.utc).isoformat()
    results["report_path"] = str(report_path)
    report_path.parent.mkdir(exist_ok=True)
    report_path.write_text(json.dumps(results, indent=2))
    return results


if __name__ == "__main__":
    summary = evaluate()
    print(summary)
    if summary["failed"]:
        raise SystemExit(1)
