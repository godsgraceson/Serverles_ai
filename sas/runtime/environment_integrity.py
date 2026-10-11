from __future__ import annotations

import hashlib
import sys
from pathlib import Path

from sas.config import SASConfig, load_config
from sas.exceptions import SecurityError


class EnvironmentGuard:
    """Detect unexpected runtime mutation (module cache / handler file changes)."""

    def __init__(self, watched: list[Path] | None = None, config: SASConfig | None = None) -> None:
        self.config = config or load_config()
        self.watched = watched or [
            self.config.project_root / "sas" / "middleware.py",
            self.config.project_root / "functions" / "inference" / "handler.py",
        ]
        self._baseline = {str(path): self._hash(path) for path in self.watched if path.exists()}
        self._sys_modules_baseline = frozenset(sys.modules.keys())

    def _hash(self, path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def check(self) -> None:
        for path in self.watched:
            if not path.exists():
                continue
            current = self._hash(path)
            expected = self._baseline.get(str(path))
            if expected and current != expected:
                raise SecurityError(f"execution environment integrity failure: {path.name} modified")
        extras = set(sys.modules.keys()) - set(self._sys_modules_baseline)
        suspicious = [name for name in extras if name.startswith("sas_persist_") or name.endswith("_backdoor")]
        if suspicious:
            raise SecurityError(f"unauthorized module injection: {suspicious}")
