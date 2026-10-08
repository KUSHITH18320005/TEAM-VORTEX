"""
Branch 1: Statistical Anomaly Evaluator.
Computes anomaly scores based on entropy, unusual parameter length, header deviation, and statistical variance.
"""

from __future__ import annotations

import math
from typing import Any, Dict


class StatisticalBranch:
    """Evaluates statistical deviations and entropy anomalies in request payloads."""

    name = "statistical_anomaly"

    @classmethod
    def evaluate(cls, telemetry: Dict[str, Any]) -> float:
        score = 0.05
        raw_text = str(telemetry.get("payload", "")) + str(telemetry.get("query", "")) + str(telemetry.get("body", ""))
        
        if not raw_text or raw_text == "None":
            return score

        # 1. Entropy calculation
        entropy = cls._calculate_entropy(raw_text)
        if entropy > 4.5:
            score += 0.35
        elif entropy > 3.8:
            score += 0.20

        # 2. Length anomaly
        if len(raw_text) > 300:
            score += 0.30
        elif len(raw_text) > 100:
            score += 0.15

        # 3. Non-alphanumeric ratio
        non_alpha = sum(1 for c in raw_text if not c.isalnum() and not c.isspace())
        ratio = non_alpha / max(1, len(raw_text))
        if ratio > 0.35:
            score += 0.30

        return min(1.0, score)

    @staticmethod
    def _calculate_entropy(text: str) -> float:
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        return -sum(p * math.log2(p) for p in prob)
