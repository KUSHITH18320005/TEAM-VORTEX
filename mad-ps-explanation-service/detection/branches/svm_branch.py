"""
Branch 7: Support Vector Machine (SVM) Branch for Explanation Service Detection Mesh.
"""

from __future__ import annotations

import logging
from typing import Any, Dict
from models.svm_engine import svm_engine

logger = logging.getLogger("mad_ps_explanation.svm_branch")


class SVMBranch:
    """Branch 7: High-dimensional TF-IDF & Flow SVM Evaluator."""

    name = "svm_classifier"
    port = 8007
    weight = 1.15

    @classmethod
    def evaluate(cls, telemetry: Dict[str, Any]) -> float:
        try:
            res = svm_engine.score_telemetry(telemetry)
            return float(res.get("score", 0.05))
        except Exception as exc:
            logger.warning("[SVM Branch] Scoring fallback: %s", exc)
            return 0.05
