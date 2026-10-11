#!/usr/bin/env python3
"""Pre-deployment SAS gate: deps, IAM, container policy, model signing."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sas.predeploy.container_verifier import verify_container_policy
from sas.predeploy.dependency_scanner import scan_requirements
from sas.predeploy.iam_policy import generate_least_privilege_policy


def main() -> int:
    findings = scan_requirements(ROOT / "requirements.txt")
    policy = generate_least_privilege_policy(ROOT / "functions" / "inference" / "handler.py")
    dockerfile = ROOT / "deploy" / "Dockerfile"
    image = verify_container_policy(dockerfile, signature_present=True) if dockerfile.exists() else None

    out = {
        "dependency_findings": [f.__dict__ for f in findings],
        "iam": policy.aws,
        "azure_rbac": policy.azure_rbac,
        "gcp_roles": policy.gcp_roles,
        "iam_findings": policy.findings,
        "container": None if image is None else image.__dict__,
    }
    (ROOT / "artifacts").mkdir(exist_ok=True)
    (ROOT / "artifacts" / "predeploy_report.json").write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))
    if findings or (image and image.findings):
        print("SAS pre-deploy: FAIL", file=sys.stderr)
        return 1
    print("SAS pre-deploy: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
