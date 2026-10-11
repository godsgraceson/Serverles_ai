from __future__ import annotations

from sas.config import SASConfig, load_config
from sas.forensics.incident_response import IncidentResponder
from sas.forensics.inference_patterns import InferencePatternAnalyzer
from sas.forensics.logger import ForensicLogger
from sas.runtime.environment_integrity import EnvironmentGuard
from sas.runtime.invocation_analyzer import InvocationAnalyzer
from sas.runtime.memory_isolation import MemoryIsolator
from sas.runtime.rate_limiter import RateLimiter
from sas.runtime.request_validator import RequestValidator


class ServerlessAIShield:
    """Composition root for the three SAS layers."""

    def __init__(self, n_features: int = 4, config: SASConfig | None = None) -> None:
        self.config = config or load_config()
        self.validator = RequestValidator(n_features=n_features, config=self.config)
        self.invocations = InvocationAnalyzer(config=self.config)
        self.patterns = InferencePatternAnalyzer(self.invocations)
        self.memory = MemoryIsolator(config=self.config)
        self.env = EnvironmentGuard(config=self.config)
        self.limiter = RateLimiter(config=self.config)
        self.logger = ForensicLogger(config=self.config)
        self.responder = IncidentResponder(self.logger)


_SHIELD: ServerlessAIShield | None = None


def get_shield(n_features: int = 4) -> ServerlessAIShield:
    global _SHIELD
    if _SHIELD is None:
        _SHIELD = ServerlessAIShield(n_features=n_features)
    return _SHIELD


def reset_shield() -> None:
    global _SHIELD
    _SHIELD = None
