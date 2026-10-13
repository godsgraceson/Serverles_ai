from __future__ import annotations

import functools
import logging
import time

from sas.exceptions import IncidentAction, SecurityError
from sas.shield import get_shield

logger = logging.getLogger("SAS-Middleware")
logger.setLevel(logging.INFO)


def secure_function(
    validate_input: bool = True,
    memory_isolation: bool = True,
    execution_monitoring: bool = True,
    model_extraction_protection: bool = True,
    n_features: int = 4,
):
    """Handler wrapper — SAS middleware integration (paper Fig. 2)."""

    def decorator(func):
        @functools.wraps(func)
        def wrapper(event, context=None):
            shield = get_shield(n_features=n_features)
            start = time.time()
            event = event or {}
            client_id = str(event.get("client_id") or event.get("requestContext", {}).get("identity", {}).get("sourceIp") or "anonymous")

            try:
                shield.env.check()
            except SecurityError as exc:
                shield.responder.decide(client_id, integrity_failed=True)
                return {"statusCode": 500, "body": str(exc), "sas_action": IncidentAction.ROLLBACK}

            if not shield.limiter.allow(client_id):
                shield.logger.record("rate_limit", {"client_id": client_id})
                return {"statusCode": 429, "body": "SAS Security: rate limited", "sas_action": IncidentAction.THROTTLE}

            validation = None
            if validate_input:
                validation = shield.validator.validate(event)
                action = shield.responder.decide(client_id, validation=validation)
                if action != IncidentAction.ALLOW:
                    status_code = validation.status_code if not validation.ok else 403
                    message = validation.message if not validation.ok else "SAS Security: client blocked"
                    return {"statusCode": status_code, "body": message, "sas_action": action}

            pre_verdict = None
            if model_extraction_protection:
                pre_verdict = shield.invocations.inspect(client_id, event.get("data") or [])
                action = shield.responder.decide(client_id, verdict=pre_verdict)
                if action != IncidentAction.ALLOW:
                    return {
                        "statusCode": 429,
                        "body": "SAS Security: suspicious query pattern",
                        "sas_action": action,
                        "reasons": pre_verdict.reasons,
                    }

            shield.memory.bind_globals(func.__globals__)
            response = None
            try:
                response = func(event, context)
            finally:
                if memory_isolation:
                    cleaned = shield.memory.cleanup(func.__globals__)
                    if execution_monitoring:
                        logger.info("memory isolation removed %s artifacts", cleaned)

            duration = time.time() - start
            prediction = None
            if isinstance(response, dict):
                prediction = response.get("prediction")
                if not shield.config.return_confidence_scores:
                    response.pop("confidence", None)
                    response.pop("proba", None)
            post = shield.patterns.observe(
                client_id, event.get("data") or [], prediction, duration, verdict=pre_verdict
            )
            shield.logger.record(
                "invocation",
                {
                    "client_id": client_id,
                    "duration_s": round(duration, 6),
                    "status": (response or {}).get("statusCode", 200) if isinstance(response, dict) else 200,
                    "reasons": post.reasons,
                },
            )
            if execution_monitoring:
                logger.info("execution %.4fs client=%s", duration, client_id)
            return response

        return wrapper

    return decorator
