"""
Passive Telemetry Inspector & Multi-Branch ML Detection Evaluator.
Evaluates incoming client telemetry payloads passively across all 8 ML/DL branches.
NO active outbound HTTP requests or probing. Fully passive ingestion monitoring.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from .classifier import MetaClassifier
from .branches.semantic import SemanticBranch
from .branches.statistical import StatisticalBranch

logger = logging.getLogger("mad_ps_detection.evaluator")


class LiveTrafficInspector:
    """Passive telemetry evaluator and multi-branch ML detection coordinator."""

    @classmethod
    def inspect_raw_telemetry(
        cls,
        telemetry: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Direct passive evaluation of ingested client telemetry across all 8 ML/DL branches.
        """
        category, confidence, severity, branch_scores = MetaClassifier.evaluate_telemetry(telemetry)
        payload_str = str(telemetry.get("payload", "") or "") + " " + str(telemetry.get("endpoint", "") or "")
        entropy = StatisticalBranch.calculate_entropy(payload_str)
        matched_tokens = SemanticBranch.extract_matched_tokens(payload_str)

        return {
            "category": category,
            "confidence": confidence,
            "severity": severity,
            "branch_scores": branch_scores,
            "entropy": entropy,
            "matched_tokens": matched_tokens,
            "is_threat": bool(confidence >= 0.70 and category != "BENIGN_TELEMETRY"),
        }
