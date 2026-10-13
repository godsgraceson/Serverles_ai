# Serverless AI Shield (SAS)

M.Tech implementation of the **Serverless AI Shield** architecture from:

> Pathade et al., *Serverless AI Security: Attack Surface Analysis and Runtime Protection Mechanisms for FaaS-Based Machine Learning*

The system is a **defense-in-depth** stack around FaaS ML inference: pre-deployment validation, runtime middleware, and post-execution forensics.

## Quick start

```bash
cd IMPLEMENTATION/serverless_ai_shield_project
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python model_setup.py
python scripts/predeploy_validate.py
python -m pytest tests/ -q
python scripts/evaluate.py
python scripts/attack_emulator.py
python scripts/run_local.py
```

Then:

```bash
curl -s http://127.0.0.1:8080/predict \
  -H 'Content-Type: application/json' \
  -d '{"client_id":"demo","data":[[0.2,-0.1,0.4,0.0]]}'
```

## What was implemented

- Signed sklearn model load (`artifacts/model.pkl` + registry hash)
- Middleware wrapping the inference handler (AWS/Azure/GCP-shaped events)
- Dependency, IAM, and container policy gates
- Extraction-like query throttling, malformed/outlier rejection, memory cleanup
- Forensic JSONL log under `logs/`
- IaC templates under `iac/` (not applied unless you choose to)

## How it works

The project follows the paper's three-layer SAS design:

1. Pre-deployment checks run before the function is shipped. `scripts/predeploy_validate.py` scans direct ML dependencies against `data/vuln_db.json`, generates a least-privilege IAM/RBAC/GCP permission set from the handler source, checks the Docker base image allow-list, and writes `artifacts/predeploy_report.json`.
2. Runtime protection is applied by `@secure_function` in `sas/middleware.py`. Every request is normalized, rate-limited, checked for malformed or statistical-outlier input, inspected for extraction-like query volume, passed to the protected ML handler, stripped of confidence scores by default, then logged.
3. Post-execution forensics are written as JSON Lines in `logs/sas_forensics.jsonl`, so you can show which clients were allowed, rejected, blocked, or throttled.

The ML model itself is intentionally small for a local M.Tech demo: `model_setup.py` trains a 4-feature sklearn Logistic Regression model, stores it in `artifacts/model.pkl`, and signs its SHA-256 in `data/model_registry.json`. The research contribution being demonstrated is the serverless AI security wrapper around inference, not a high-accuracy domain model.

## How to verify the simulated attacks

Run:

```bash
python scripts/evaluate.py
```

This now writes `artifacts/evaluation_report.json` and prints pass/fail checks for:

- benign inference: proves normal users still receive predictions
- confidence scores stripped: reduces model-extraction signal
- malformed input blocked: simulates bad event/API payloads
- statistical outlier blocked: simulates adversarial or out-of-distribution inputs
- extraction-like query volume throttled: simulates repeated black-box probing
- tampered hash rejected: simulates model artifact tampering
- dependency scan completed: verifies the supply-chain gate runs
- IAM policy generated: verifies least-privilege policy generation

For a fuller paper-category demo, run:

```bash
python scripts/attack_emulator.py
```

This writes `artifacts/attack_emulation_report.json` and safely emulates:

- malformed event injection
- adversarial/outlier input
- model-extraction style query volume
- burst invocation behavior
- model artifact tampering
- vulnerable dependency selection
- untrusted/root container image policy failure
- dangerous runtime primitive detection

To inspect forensic evidence after the run:

```bash
tail -n 20 logs/sas_forensics.jsonl
cat artifacts/evaluation_report.json
cat artifacts/attack_emulation_report.json
cat artifacts/predeploy_report.json
```

You can also verify the same controls through the local HTTP simulator:

```bash
python scripts/run_local.py
```

In another terminal:

```bash
curl -s http://127.0.0.1:8080/health

curl -s http://127.0.0.1:8080/predict \
  -H 'Content-Type: application/json' \
  -d '{"client_id":"demo-ok","data":[[0.2,-0.1,0.4,0.0]]}'

curl -s http://127.0.0.1:8080/predict \
  -H 'Content-Type: application/json' \
  -d '{"client_id":"demo-bad","data":"not-a-matrix"}'

curl -s http://127.0.0.1:8080/predict \
  -H 'Content-Type: application/json' \
  -d '{"client_id":"demo-outlier","data":[[999,999,999,999]]}'
```

For extraction/burst simulation, send repeated requests with the same `client_id`. The default live server threshold is higher than the evaluation script, so a fast burst of about 15 requests demonstrates burst throttling; `scripts/evaluate.py` lowers `SAS_EXTRACTION_THRESHOLD` to make the test quick and repeatable.

## What was not implemented

Section IV attack generators (cold-start DoS, dependency poisoning packages, model-extraction training loops, side channels, privilege-escalation exploits) are **out of scope**. Evaluation uses **labeled policy-violating request patterns** against the shield.

In other words: the project checks whether SAS detects and blocks representative defensive signals. It does not launch real attacks against AWS, Azure, GCP, PyPI, containers, or another system. To test real attacks ethically, use an isolated lab account, formal authorization, and an institutional review/safety process; do not aim traffic or exploit attempts at systems you do not own or have written permission to test.

## Layout

See `ARCHITECTURE.md` for the paper-to-code mapping.
