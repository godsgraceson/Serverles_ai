from __future__ import annotations

import gc
import os
from pathlib import Path

from sas.config import SASConfig, load_config


class MemoryIsolator:
    """Clear invocation-scoped state so container reuse cannot leak artifacts."""

    def __init__(self, config: SASConfig | None = None) -> None:
        self.config = config or load_config()
        self._scratch = Path(os.environ.get("SAS_SCRATCH", str(self.config.project_root / ".sas_scratch")))
        self._scratch.mkdir(parents=True, exist_ok=True)

    def bind_globals(self, owner: dict) -> None:
        owner["_sas_invocation_state"] = {}

    def cleanup(self, owner: dict | None = None) -> int:
        removed = 0
        for path in list(self._scratch.glob("*")):
            try:
                if path.is_file():
                    path.unlink()
                    removed += 1
            except OSError:
                continue
        tmp = self.config.tmp_dir
        if tmp.exists():
            for path in tmp.glob("sas_inv_*"):
                try:
                    path.unlink()
                    removed += 1
                except OSError:
                    continue
        if owner is not None:
            owner.pop("_sas_invocation_state", None)
            for key in list(owner.keys()):
                if key.startswith("_cache_untrusted_"):
                    owner.pop(key, None)
        gc.collect()
        return removed
