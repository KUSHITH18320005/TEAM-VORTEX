"""
Branch 8: Deep Neural Network (DNN) Branch.
Evaluates:
- M2a: Deep MLP (256->128->64->32 with BatchNorm & Dropout) on network/behavioral flows.
- M2b: 1D-CNN with parallel multi-scale kernels (3/5/7) on character-level raw payload sequences.
Exposes /internal/score on port 8008.
"""

from __future__ import annotations

import logging
from typing import Any, Dict
from models.dnn_engine import dnn_engine

logger = logging.getLogger("mad_ps_detection.dnn_branch")


class DNNBranch:
    """Branch 8: Deep MLP & Payload 1D-CNN Evaluator."""

    name = "deep_neural_network"
    port = 8008
    weight = 1.25

    @classmethod
    def evaluate(cls, telemetry: Dict[str, Any]) -> float:
        """
        Evaluates incoming telemetry payload against deep neural network architectures.
        Returns calibrated probability score.
        """
        try:
            res = dnn_engine.score_telemetry(telemetry)
            return float(res.get("score", 0.05))
        except Exception as exc:
            logger.warning("[DNN Branch] Scoring fallback: %s", exc)
            return 0.05

    @classmethod
    def get_details(cls, telemetry: Dict[str, Any]) -> Dict[str, Any]:
        """Returns comprehensive DNN classification details."""
        return dnn_engine.score_telemetry(telemetry)
