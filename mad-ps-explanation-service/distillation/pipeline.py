"""
Distillation Pipeline for MAD-PS Explanation Layer.
Handles automated retrieval of category-matched few-shot exemplars and formatting
for in-context prompt injection into Council agents.
"""

from __future__ import annotations

import json
import logging
from typing import List, Optional

from .exemplar_store import ExemplarStore
from .models import FewShotExemplar

logger = logging.getLogger("mad_ps_explanation.distillation.pipeline")


class DistillationPipeline:
    """
    Tier 1 Distillation Engine:
    Retrieves high-quality past debate demonstrations and injects them as few-shot exemplars.
    """

    def __init__(self, store: Optional[ExemplarStore] = None) -> None:
        self.store = store or ExemplarStore()

    def get_reconstruction_few_shot_prompt(self, category: str, max_examples: int = 2) -> str:
        """Format few-shot exemplars specifically for Agent 1 (Reconstruction)."""
        exemplars = self.store.get_exemplars(category, max_count=max_examples)
        if not exemplars:
            return ""

        blocks = ["\n[HIGH-CONFIDENCE HISTORICAL EXAMPLES OF GROUNDED RECONSTRUCTION]"]
        for idx, ex in enumerate(exemplars, start=1):
            demo_str = json.dumps(ex.reconstruction_demonstration, indent=2)
            blocks.append(
                f"\n--- Example {idx} ({ex.category}) ---\n"
                f"Input Summary: {ex.reconstruction_input_summary}\n"
                f"Gold Grounded Output:\n{demo_str}\n"
            )
        blocks.append("[END HISTORICAL EXAMPLES]\n")
        return "\n".join(blocks)

    def get_response_few_shot_prompt(self, category: str, max_examples: int = 2) -> str:
        """Format few-shot exemplars specifically for Agent 2 (Response)."""
        exemplars = self.store.get_exemplars(category, max_count=max_examples)
        if not exemplars:
            return ""

        blocks = ["\n[HIGH-CONFIDENCE HISTORICAL EXAMPLES OF BALANCED INCIDENT RESPONSE]"]
        for idx, ex in enumerate(exemplars, start=1):
            demo_str = json.dumps(ex.response_demonstration, indent=2)
            blocks.append(
                f"\n--- Example {idx} ({ex.category}) ---\n"
                f"Input Summary: {ex.response_input_summary}\n"
                f"Gold Response Output:\n{demo_str}\n"
            )
        blocks.append("[END HISTORICAL EXAMPLES]\n")
        return "\n".join(blocks)

    def record_transcript(self, transcript: Any) -> Any:
        """Record debate transcript to underlying exemplar store."""
        return self.store.record_transcript(transcript)
