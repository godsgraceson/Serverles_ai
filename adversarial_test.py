"""Legacy entry point used by CI. Runs defensive SAS evaluation only."""

from scripts.evaluate import evaluate

if __name__ == "__main__":
    summary = evaluate()
    if summary["failed"]:
        raise SystemExit(1)
