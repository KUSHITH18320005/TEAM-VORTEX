"""
Data models for Debate Transcripts, Human Feedback, and Distilled Few-Shot Exemplars.
"""

from __future__ import annotations

import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from schemas.incident import IncidentRecord
from schemas.report import ConsensusMetric, FinalExplanationReport, JudgeSynthesis, ReconstructionResult, ResponsePlan, RevisionFeedback


class FeedbackRating(str, Enum):
    POSITIVE = "POSITIVE"      # Thumbs-up / Confirmed by human analyst
    NEGATIVE = "NEGATIVE"      # Thumbs-down / Flagged inaccurate
    UNREVIEWED = "UNREVIEWED"  # No explicit human review yet


class HumanFeedback(BaseModel):
    """Human analyst evaluation of a council explanation report."""
    feedback_id: str
    report_id: str
    incident_id: str
    rating: FeedbackRating
    analyst_id: Optional[str] = "soc_lead"
    comments: Optional[str] = None
    created_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())


class DebateTranscript(BaseModel):
    """Complete log of a 3-agent Council debate and revision session."""
    session_id: str
    incident_id: str
    category: str
    created_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    incident_record: IncidentRecord
    reconstruction_result: ReconstructionResult
    response_plan: ResponsePlan
    judge_synthesis: JudgeSynthesis
    debate_revisions: List[RevisionFeedback]
    consensus_metric: ConsensusMetric
    final_report: FinalExplanationReport
    human_feedback: Optional[HumanFeedback] = None
    quality_score: float = Field(default=0.0, ge=0.0, le=1.0)
    is_distillation_exemplar: bool = False

    def evaluate_quality(self) -> float:
        """
        Compute empirical quality score for exemplar candidate selection.
        - Human positive feedback: 1.0
        - Human negative feedback: 0.0 (disqualified)
        - Unreviewed with Full Consensus: 0.95
        - Unreviewed with Strong Consensus: 0.85
        - Unreviewed with Partial Consensus: 0.65
        - Unreviewed with Dissent: 0.40
        """
        if self.human_feedback:
            if self.human_feedback.rating == FeedbackRating.POSITIVE:
                return 1.0
            elif self.human_feedback.rating == FeedbackRating.NEGATIVE:
                return 0.0

        status = self.consensus_metric.status
        if status == "FULL_CONSENSUS":
            return 0.95
        elif status == "STRONG_CONSENSUS":
            return 0.85
        elif status == "PARTIAL_CONSENSUS":
            return 0.65
        return 0.40


class FewShotExemplar(BaseModel):
    """A distilled, high-quality input-output demonstration for in-context distillation."""
    exemplar_id: str
    category: str
    source_incident_id: str
    quality_score: float
    reconstruction_input_summary: str
    reconstruction_demonstration: Dict[str, Any]
    response_input_summary: str
    response_demonstration: Dict[str, Any]
    judge_demonstration: Dict[str, Any]
    created_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
