from __future__ import annotations

from sas.exceptions import IncidentAction
from sas.forensics.logger import ForensicLogger
from sas.runtime.invocation_analyzer import InvocationVerdict
from sas.runtime.request_validator import ValidationResult


class IncidentResponder:
    def __init__(self, logger: ForensicLogger | None = None) -> None:
        self.logger = logger or ForensicLogger()
        self.blocked_clients: set[str] = set()
        self.throttled_clients: set[str] = set()
        self.rollback_requested = False

    def decide(
        self,
        client_id: str,
        validation: ValidationResult | None = None,
        verdict: InvocationVerdict | None = None,
        integrity_failed: bool = False,
    ) -> str:
        if integrity_failed:
            self.rollback_requested = True
            self.logger.record("rollback", {"client_id": client_id, "action": IncidentAction.ROLLBACK})
            return IncidentAction.ROLLBACK
        if client_id in self.blocked_clients:
            return IncidentAction.BLOCK
        if validation and not validation.ok:
            if "statistical_outlier" in validation.flags:
                self.blocked_clients.add(client_id)
                self.logger.record("block", {"client_id": client_id, "reason": validation.message})
                return IncidentAction.BLOCK
            self.logger.record("reject", {"client_id": client_id, "reason": validation.message})
            return IncidentAction.BLOCK
        if verdict and (verdict.extraction_suspected or verdict.burst_suspected):
            self.throttled_clients.add(client_id)
            self.blocked_clients.add(client_id)
            self.logger.record(
                "throttle_block",
                {"client_id": client_id, "reasons": verdict.reasons, "action": IncidentAction.THROTTLE},
            )
            return IncidentAction.THROTTLE
        return IncidentAction.ALLOW
