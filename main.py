#!/usr/bin/env python3
"""Project entry: train a signed model, then run the local SAS inference server."""

from __future__ import annotations

import os
from pathlib import Path

from model_setup import train_model


def main() -> None:
    root = Path(__file__).resolve().parent
    os.chdir(root)
    if not (root / "artifacts" / "model.pkl").exists():
        train_model()
    from scripts.run_local import main as serve

    serve()


if __name__ == "__main__":
    main()
