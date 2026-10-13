from __future__ import annotations

import os
from pathlib import Path

import joblib
from sklearn.datasets import make_classification
from sklearn.linear_model import LogisticRegression

from sas.ml_protection import sign_and_export_hash
from sas.predeploy.model_integrity import compute_sha256

ARTIFACTS = Path(__file__).resolve().parent / "artifacts"


def train_model(path: Path | None = None) -> Path:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    model_path = path or ARTIFACTS / "model.pkl"
    tmp_model_path = model_path.with_name(f"{model_path.name}.{os.getpid()}.tmp")
    x, y = make_classification(
        n_samples=800,
        n_features=4,
        n_informative=3,
        n_redundant=0,
        n_repeated=0,
        random_state=42,
    )
    model = LogisticRegression(max_iter=400)
    model.fit(x, y)
    joblib.dump(model, tmp_model_path)
    tmp_model_path.replace(model_path)
    digest = sign_and_export_hash(str(model_path), source="sklearn-trained")
    os.environ["SAS_EXPECTED_MODEL_HASH"] = digest
    print(f"[+] Model saved to {model_path}")
    print(f"export SAS_EXPECTED_MODEL_HASH={digest}")
    print(f"[+] sha256={compute_sha256(model_path)}")
    return model_path


if __name__ == "__main__":
    train_model()
