from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

ALLOWED_BASES = {
    "public.ecr.aws/lambda/python:3.11",
    "python:3.11-slim",
    "mcr.microsoft.com/azure-functions/python:4-python3.11",
}


@dataclass
class ImageReport:
    base_image: str | None
    signed: bool
    allowed_base: bool
    findings: list[str]


def verify_container_policy(dockerfile_path: str | Path, signature_present: bool = True) -> ImageReport:
    findings: list[str] = []
    base: str | None = None
    for line in Path(dockerfile_path).read_text().splitlines():
        stripped = line.strip()
        if stripped.upper().startswith("FROM "):
            base = stripped.split(None, 1)[1].split(" AS ")[0].strip()
        if "USER root" in stripped:
            findings.append("container runs as root")
    allowed = base in ALLOWED_BASES if base else False
    if not allowed:
        findings.append(f"base image not in trusted registry allow-list: {base}")
    if not signature_present:
        findings.append("image signature / provenance attestation missing")
    return ImageReport(
        base_image=base,
        signed=signature_present,
        allowed_base=allowed,
        findings=findings,
    )
