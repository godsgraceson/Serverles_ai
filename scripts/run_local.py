#!/usr/bin/env python3
"""Local FaaS simulator with SAS middleware (no cloud credentials required)."""

from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from model_setup import train_model
from functions.inference.handler import inference_handler


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._send(200, {"status": "ok", "shield": "sas"})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path not in {"/", "/invoke", "/predict"}:
            self._send(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            event = json.loads(raw.decode() or "{}")
        except json.JSONDecodeError:
            self._send(400, {"error": "invalid json"})
            return
        event.setdefault("client_id", self.headers.get("X-Client-Id", self.client_address[0]))
        result = inference_handler(event, None)
        self._send(int(result.get("statusCode", 200)), result)

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("local-faas: " + (fmt % args) + "\n")


def main() -> None:
    if not (ROOT / "artifacts" / "model.pkl").exists():
        train_model()
    os.environ.setdefault("SAS_MODEL_PATH", str(ROOT / "artifacts" / "model.pkl"))
    host = os.environ.get("SAS_HOST", "127.0.0.1")
    port = int(os.environ.get("SAS_PORT", "8080"))
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"SAS local inference on http://{host}:{port}/predict")
    server.serve_forever()


if __name__ == "__main__":
    main()
