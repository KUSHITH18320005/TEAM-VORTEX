"""
Branch 7: Support Vector Machine (SVM) Branch.
Evaluates high-dimensional TF-IDF web payload representations (Linear Kernel)
and network flow non-linear boundary characteristics (RBF Kernel).
Exposes /internal/score on port 8007 with verified StandardScaler.
"""

from __future__ import annotations

import logging
from typing import Any, Dict
from models.svm_engine import svm_engine

logger = logging.getLogger("mad_ps_detection.svm_branch")


class SVMBranch:
    """Branch 7: High-dimensional TF-IDF & Flow SVM Evaluator."""

    name = "svm_classifier"
    port = 8007
    weight = 1.15

    @classmethod
    def evaluate(cls, telemetry: Dict[str, Any]) -> float:
        """
        Evaluates incoming telemetry payload against trained SVM models.
        Returns calibrated probability score.
        """
        try:
            res = svm_engine.score_telemetry(telemetry)
            return float(res.get("score", 0.05))
        except Exception as exc:
            logger.warning("[SVM Branch] Scoring fallback: %s", exc)
            return 0.05

    @classmethod
    def get_details(cls, telemetry: Dict[str, Any]) -> Dict[str, Any]:
        """Returns comprehensive SVM classification details."""
        return svm_engine.score_telemetry(telemetry)
