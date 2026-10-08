"""
Branch 5: Rate & Frequency Anomaly Branch.
Detects burst rates, credential stuffing attacks, OTP brute-forcing, and resource exhaustion.
"""

from __future__ import annotations

from typing import Any, Dict


class RateAnomalyBranch:
    """Evaluates request velocities, failed auth bursts, and rate-limit bypasses."""

    name = "rate_frequency_anomaly"

    @classmethod
    def evaluate(cls, telemetry: Dict[str, Any]) -> float:
        req_per_sec = float(telemetry.get("requests_per_sec", 0))
        failed_count = int(telemetry.get("failed_count_1min", 0) or telemetry.get("failed_attempts_last_min", 0))
        
        # High velocity credential stuffing
        if failed_count > 100 or req_per_sec > 50:
            return 0.98
        elif failed_count > 30 or req_per_sec > 20:
            return 0.88
        elif failed_count > 10 or req_per_sec > 10:
            return 0.70

        return 0.05
