"""
Branch 4: Graph Correlation Branch.
Correlates IP hops, internal network loopback addresses, SSRF target metadata URLs,
and cross-service topology anomalies.
"""

from __future__ import annotations

import re
from typing import Any, Dict


class GraphBranch:
    """Correlates target IP addresses and internal cloud metadata endpoints."""

    name = "graph_correlation"

    SSRF_TARGETS = [
        r"169\.254\.169\.254",  # AWS/GCP/Azure instance metadata
        r"127\.0\.0\.1",
        r"localhost",
        r"0\.0\.0\.0",
        r"10\.\d+\.\d+\.\d+",
        r"192\.168\.\d+\.\d+",
        r"172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+",
    ]

    @classmethod
    def evaluate(cls, telemetry: Dict[str, Any]) -> float:
        target_url = str(telemetry.get("target_url", "")) + " " + str(telemetry.get("redirect_url", "")) + " " + str(telemetry.get("payload", ""))
        
        for p in cls.SSRF_TARGETS:
            if re.search(p, target_url):
                return 0.96

        # Check GraphQL depth probe
        if telemetry.get("query_depth", 0) > 8 or telemetry.get("has_introspection"):
            return 0.92

        return 0.05
