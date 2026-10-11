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

## What was not implemented

Section IV attack generators (cold-start DoS, dependency poisoning packages, model-extraction training loops, side channels, privilege-escalation exploits) are **out of scope**. Evaluation uses **labeled policy-violating request patterns** against the shield.

## Layout

See `ARCHITECTURE.md` for the paper-to-code mapping.
