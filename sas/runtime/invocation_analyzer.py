from __future__ import annotations

import statistics
import time
from collections import defaultdict, deque
from dataclasses import dataclass

from sas.config import SASConfig, load_config


@dataclass
class InvocationVerdict:
    cold_start_suspected: bool
    extraction_suspected: bool
    burst_suspected: bool
    reasons: list[str]


class InvocationAnalyzer:
    """Baselines invocation timing/frequency (paper: function invocation analysis)."""

    def __init__(self, config: SASConfig | None = None) -> None:
        self.config = config or load_config()
        self._latencies: deque[float] = deque(maxlen=200)
        self._client_times: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=500))
        self._client_features: dict[str, deque[tuple]] = defaultdict(lambda: deque(maxlen=500))

    def record_latency(self, duration_s: float) -> None:
        self._latencies.append(duration_s)

    def inspect(self, client_id: str, features: list, duration_s: float | None = None) -> InvocationVerdict:
        now = time.time()
        times = self._client_times[client_id]
        times.append(now)
        window = [t for t in times if now - t <= self.config.extraction_query_window]
        reasons: list[str] = []
        extraction = len(window) >= self.config.extraction_query_threshold
        if extraction:
            reasons.append("query volume exceeds extraction threshold in sliding window")

        feat_key = tuple(round(float(x), 4) for x in _flatten(features)[:32])
        hist = self._client_features[client_id]
        hist.append(feat_key)
        unique_ratio = len(set(hist)) / max(len(hist), 1)
        if len(hist) >= 20 and unique_ratio > 0.9:
            extraction = True
            reasons.append("systematic unique-query exploration of input space")

        burst = len([t for t in times if now - t <= 2.0]) >= 15
        if burst:
            reasons.append("short-window invocation burst")

        cold = False
        if duration_s is not None and self._latencies:
            warm = statistics.median(self._latencies)
            if warm > 0 and duration_s / warm >= self.config.cold_start_ratio_alert:
                cold = True
                reasons.append("latency signature consistent with cold-start probing")
        if duration_s is not None:
            self.record_latency(duration_s)
        return InvocationVerdict(cold, extraction, burst, reasons)


def _flatten(value) -> list[float]:
    if isinstance(value, (int, float)):
        return [float(value)]
    if isinstance(value, list):
        out: list[float] = []
        for item in value:
            out.extend(_flatten(item))
        return out
    return []
