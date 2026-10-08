"""
Branch 8: Deep Neural Network (DNN) Branch for Explanation Service Detection Mesh.
"""

from __future__ import annotations

import logging
from typing import Any, Dict
from models.dnn_engine import dnn_engine

logger = logging.getLogger("mad_ps_explanation.dnn_branch")


class DNNBranch:
    """Branch 8: Deep MLP & Payload 1D-CNN Evaluator."""

    name = "deep_neural_network"
    port = 8008
    weight = 1.25

    @classmethod
    def evaluate(cls, telemetry: Dict[str, Any]) -> float:
        try:
            res = dnn_engine.score_telemetry(telemetry)
            return float(res.get("score", 0.05))
        except Exception as exc:
            logger.warning("[DNN Branch] Scoring fallback: %s", exc)
            return 0.05
