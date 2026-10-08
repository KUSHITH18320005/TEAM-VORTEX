"""
Pydantic schemas for Grounded Timeline with LLM Narration (Task D2).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AnnotatedTimelineEntry(BaseModel):
    """An individual verified telemetry entry enriched with LLM narrative annotation."""
    step_number: int
    timestamp: str
    action: str
    source_ip: Optional[str] = None
    endpoint: Optional[str] = None
    status_code: Optional[int] = None
    stage: str = Field(..., description="RECONNAISSANCE, INITIAL_PROBE, EXPLOITATION, DATA_ACCESS, DETECTION")
    narration: str = Field(..., description="Agent 1 grounded explanation of attacker intent and outcome for this specific log event")
    is_grounded_telemetry: bool = Field(default=True, description="True certifies that this entry is tied directly to raw log telemetry")
    raw_log_ref: Dict[str, Any] = Field(default_factory=dict, description="Underlying telemetry fields from mesh")


class GroundedTimeline(BaseModel):
    """
    Chronological sequence of verified raw log entries layered with Agent 1 reconstruction narration.
    """
    incident_id: str
    campaign_id: Optional[str] = None
    total_events: int
    time_span_seconds: float = Field(default=0.0, description="Elapsed time in seconds between first and last event")
    entries: List[AnnotatedTimelineEntry] = Field(default_factory=list)
