from __future__ import annotations

import json


def normalize_event(event: dict) -> dict:
    """Map API Gateway / Azure HTTP / GCF HTTP payloads to SAS's canonical event."""
    if not isinstance(event, dict):
        return {"data": event}
    if "data" in event:
        return event
    body = event.get("body")
    if isinstance(body, str):
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            parsed = {}
        if isinstance(parsed, dict):
            event = {**event, **parsed}
    headers = event.get("headers") or {}
    client = (
        event.get("client_id")
        or headers.get("x-client-id")
        or event.get("requestContext", {}).get("identity", {}).get("sourceIp")
        or "anonymous"
    )
    return {"client_id": client, "data": event.get("data")}
