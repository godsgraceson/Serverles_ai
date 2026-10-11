# Serverless AI Shield (SAS) — architecture mapped to the paper

Source: Pathade, Dhimam, Lareb, Ahmad, *Serverless AI Security: Attack Surface Analysis and Runtime Protection Mechanisms for FaaS-Based Machine Learning* (arXiv:2601.11664).

This repository implements **contribution C3 (runtime protection framework)** and a local subset of **C4 (toolkit)**. It does **not** reproduce offensive proof-of-concepts from Section IV.

## Decision this system informs

Whether an ML inference function can be deployed on a FaaS platform with SAS controls enabled without breaking benign traffic, and which control layers to turn on first (incremental adoption, paper Section VII.D).

## Three layers (Section V.A)

```
CI/CD / pre-deploy          Runtime (middleware wrap)         Post-execution
-------------------          -------------------------         --------------
dependency scan              request validation                inference pattern log
model hash + registry        extraction query window           throttle / block / rollback
least-privilege IAM AST      rate limit                        forensic JSONL
container allow-list         memory isolation
                             environment integrity
```

## Folder map

| Path | Paper mechanism |
| --- | --- |
| `sas/predeploy/dependency_scanner.py` | Vulnerable ML dependency detection |
| `sas/predeploy/model_integrity.py` | Cryptographic model provenance |
| `sas/predeploy/iam_policy.py` | Least-privilege IAM generation |
| `sas/predeploy/container_verifier.py` | Image/base allow-list |
| `sas/runtime/request_validator.py` | Input + statistical outlier filter |
| `sas/runtime/invocation_analyzer.py` | Cold-start / extraction / burst patterns |
| `sas/runtime/memory_isolation.py` | Cross-invocation cleanup |
| `sas/runtime/environment_integrity.py` | Runtime file/module integrity |
| `sas/forensics/*` | Logging and automated response |
| `sas/middleware.py` | Handler wrapper (Fig. 2) |
| `functions/inference/handler.py` | Protected inference function |
| `sas/adapters/normalize.py` | AWS / Azure / GCP event shapes |
| `iac/` | CloudFormation, Terraform, Bicep templates |
| `scripts/evaluate.py` | Defensive detection/latency checks |

## Threat coverage (taxonomy Table I) — defensive only

| Category | What SAS does here |
| --- | --- |
| Function-level | Timing/burst heuristics, `/tmp` and scratch cleanup, signed handler files |
| Model-specific | Query-volume extraction throttle, hard labels by default, statistical input filter |
| Infrastructure | Generated least-privilege IAM JSON / RBAC / GCP roles |
| Supply chain | Requirements advisory index, model registry, Dockerfile allow-list |

## Local vs cloud

The default runtime is `scripts/run_local.py` (HTTP FaaS simulator) so the M.Tech demo runs without cloud credentials. The same `lambda_handler` / `azure_http_handler` / `gcp_http_handler` entry points are wired for later platform deploy.
