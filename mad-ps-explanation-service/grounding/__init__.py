"""
Data Grounding & Retrieval Layer for Conversational SOC Assistant (Task L2).
Enforces zero-hallucination data grounding across telemetry, aggregate stats,
mesh health topology, and Phase F benchmark metrics.
"""

from .models import GroundingContext, GroundingCitation, GroundingSourceType
from .retriever import GroundingRetriever

__all__ = ["GroundingContext", "GroundingCitation", "GroundingSourceType", "GroundingRetriever"]
