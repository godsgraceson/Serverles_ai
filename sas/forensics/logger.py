from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from sas.config import SASConfig, load_config


class ForensicLogger:
    def __init__(self, config: SASConfig | None = None) -> None:
        self.config = config or load_config()
        self.path = Path(self.config.forensic_log_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, event_type: str, payload: dict) -> None:
        row = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            **payload,
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row) + "\n")
