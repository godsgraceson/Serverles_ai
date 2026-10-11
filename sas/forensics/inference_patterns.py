from __future__ import annotations

from collections import defaultdict

from sas.runtime.invocation_analyzer import InvocationAnalyzer, InvocationVerdict


class InferencePatternAnalyzer:
    """Correlate request distributions after execution (paper Section V.B.3)."""

    def __init__(self, invocation_analyzer: InvocationAnalyzer | None = None) -> None:
        self.invocations = invocation_analyzer or InvocationAnalyzer()
        self._label_hist: dict[str, dict[int, int]] = defaultdict(lambda: defaultdict(int))

    def observe(
        self,
        client_id: str,
        features: list,
        prediction: list | None,
        duration_s: float,
        verdict: InvocationVerdict | None = None,
    ) -> InvocationVerdict:
        if verdict is None:
            verdict = self.invocations.inspect(client_id, features, duration_s)
        elif duration_s is not None:
            self.invocations.record_latency(duration_s)
        if prediction:
            try:
                label = int(prediction[0])
                self._label_hist[client_id][label] += 1
            except (TypeError, ValueError, IndexError):
                pass
        return verdict
