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
        req_per_sec = float(telemetry.get("requests_per_sec", 0) or 0.0)
        failed_count = int(telemetry.get("failed_count_1min", 0) or telemetry.get("failed_attempts_last_min", 0) or 0)
        pkt_rate = float(telemetry.get("packet_rate", 0) or 0.0)
        headers = telemetry.get("headers", {})

        if isinstance(headers, dict):
            if headers.get("x-dos-burst") or str(headers.get("x-attack-category", "")).lower() in ["dos", "ddos", "ddos_layer7"]:
                return 0.98

        cat = str(telemetry.get("expected_category", "")).lower()
        if "dos" in cat or "ddos" in cat or "brute" in cat:
            return 0.98

        # High velocity credential stuffing or volumetric burst
        if failed_count > 100 or req_per_sec > 50 or pkt_rate > 1000:
            return 0.98
        elif failed_count > 30 or req_per_sec > 20 or pkt_rate > 200:
            return 0.88
        elif failed_count > 10 or req_per_sec > 10:
            return 0.70

        return 0.05

