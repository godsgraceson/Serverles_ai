from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from sas.config import SASConfig, load_config
from sas.exceptions import SecurityError


def compute_sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass
class ModelManifest:
    path: str
    sha256: str
    source: str
    signed_at: str
    algorithm: str = "sha256"


class ModelRegistry:
    """Cryptographic provenance store (paper: model integrity verification)."""

    def __init__(self, registry_path: str | Path | None = None, config: SASConfig | None = None):
        self.config = config or load_config()
        self.registry_path = Path(registry_path or self.config.project_root / "data" / "model_registry.json")
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)
        self._records: dict[str, dict] = {}
        if self.registry_path.exists():
            self._records = json.loads(self.registry_path.read_text())

    def sign(self, model_path: str | Path, source: str = "local-signed") -> ModelManifest:
        path = Path(model_path)
        if source not in self.config.trusted_model_sources:
            raise SecurityError(f"Untrusted model source: {source}")
        manifest = ModelManifest(
            path=str(path.resolve()),
            sha256=compute_sha256(path),
            source=source,
            signed_at=datetime.now(timezone.utc).isoformat(),
        )
        self._records[manifest.path] = asdict(manifest)
        self.registry_path.write_text(json.dumps(self._records, indent=2))
        return manifest

    def verify(self, model_path: str | Path, expected_hash: str | None = None) -> ModelManifest:
        path = Path(model_path)
        if not path.exists():
            raise SecurityError(f"Model file not found: {path}")
        actual = compute_sha256(path)
        expected = expected_hash or self.config.expected_model_hash
        record = self._records.get(str(path.resolve())) or self._records.get(str(path))
        if expected and actual != expected:
            raise SecurityError("Model integrity verification failed. Potential tampering detected.")
        if record and record.get("sha256") != actual:
            raise SecurityError("Model hash does not match signed registry provenance.")
        if expected is None and record is None:
            raise SecurityError("No expected hash or registry entry; refuse unsigned model load.")
        source = record["source"] if record else "env-hash"
        return ModelManifest(
            path=str(path),
            sha256=actual,
            source=source,
            signed_at=record["signed_at"] if record else datetime.now(timezone.utc).isoformat(),
        )
