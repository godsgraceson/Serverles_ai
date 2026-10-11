from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from packaging.version import InvalidVersion, Version

REQ_LINE = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*(?:([=<>!~]+)\s*([A-Za-z0-9_.+-]+))?")


@dataclass
class Finding:
    package: str
    specified: str | None
    severity: str
    reason: str


def _parse_requirements(text: str) -> list[tuple[str, str | None]]:
    packages: list[tuple[str, str | None]] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        match = REQ_LINE.match(line)
        if not match:
            continue
        packages.append((match.group(1).lower().replace("_", "-"), match.group(3)))
    return packages


def _is_below(specified: str | None, unsafe_below: str) -> bool:
    if specified is None:
        return True
    try:
        return Version(specified) < Version(unsafe_below)
    except InvalidVersion:
        return True


def scan_requirements(requirements_path: str | Path, vuln_db_path: str | Path | None = None) -> list[Finding]:
    """Validate direct dependencies against the local ML advisory index."""
    req_path = Path(requirements_path)
    db_path = Path(vuln_db_path or Path(__file__).resolve().parents[2] / "data" / "vuln_db.json")
    db = json.loads(db_path.read_text())["packages"]
    findings: list[Finding] = []
    for name, version in _parse_requirements(req_path.read_text()):
        advisory = db.get(name) or db.get(name.replace("-", ""))
        if not advisory:
            continue
        if _is_below(version, advisory["unsafe_below"]):
            findings.append(
                Finding(
                    package=name,
                    specified=version,
                    severity="high",
                    reason=advisory["reason"],
                )
            )
    return findings
