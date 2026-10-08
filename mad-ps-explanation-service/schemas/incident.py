"""
Pydantic schemas for Incident records from mad-ps-detection-api (Phase E/K detection mesh).
"""

from __future__ import annotations

import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class TimelineEvent(BaseModel):
    """An individual linked event in an incident or campaign timeline."""
    event_id: Optional[str] = None
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    action: str = Field(..., description="Action description, e.g. GET /api/v1/user/1042")
    source_ip: Optional[str] = None
    status_code: Optional[int] = None
    user_id: Optional[str] = None
    payload_summary: Optional[str] = None
    risk_score: Optional[float] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class IncidentRecord(BaseModel):
    """
    Incident record emitted by mad-ps-detection-api.
    Contains detection mesh branch scores, raw log evidence, and campaign correlation.
    """
    incident_id: str = Field(..., description="Unique incident identifier, e.g. INC-2026-9041-01")
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    category: str = Field(..., description="Attack category, e.g. IDOR, SQLi, Credential Stuffing, Mass Assignment")
    severity: str = Field(default="HIGH", description="Incident severity: CRITICAL, HIGH, MEDIUM, LOW")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Overall detection mesh confidence score")
    contributing_branch_scores: Dict[str, float] = Field(
        default_factory=dict,
        description="Confidence scores from detection branches (statistical, semantic, sequence, graph, etc.)",
    )
    raw_log_details: Dict[str, Any] = Field(
        default_factory=dict,
        description="Raw telemetry details (HTTP method, endpoint, headers, client IP, payload, response latency)",
    )
    campaign_id: Optional[str] = Field(
        default=None,
        description="Correlated campaign ID if linked with multi-stage attack mesh",
    )
    timeline_events: List[TimelineEvent] = Field(
        default_factory=list,
        description="Sequence of linked timeline events leading up to and during the incident",
    )
    affected_endpoints: List[str] = Field(default_factory=list)
    affected_entities: List[str] = Field(default_factory=list)
    source_ip: Optional[str] = None
    destination_service: Optional[str] = None

    def to_grounding_context(self) -> str:
        """Format incident fields into a strictly bounded grounding context for LLM agents."""
        timeline_str = "\n".join(
            f"  - [{e.timestamp}] {e.action} (IP: {e.source_ip or 'N/A'}, Status: {e.status_code or 'N/A'}, Payload: {e.payload_summary or 'None'})"
            for e in self.timeline_events
        ) if self.timeline_events else "  - No additional linked timeline events provided."

        scores_str = "\n".join(
            f"  - {branch}: {score:.3f}"
            for branch, score in self.contributing_branch_scores.items()
        ) if self.contributing_branch_scores else "  - Default mesh aggregated confidence only."

        raw_logs_str = "\n".join(
            f"  - {k}: {v}" for k, v in self.raw_log_details.items()
        ) if self.raw_log_details else "  - No raw log details attached."

        return (
            f"INCIDENT IDENTIFIER: {self.incident_id}\n"
            f"TIMESTAMP: {self.timestamp}\n"
            f"ATTACK CATEGORY: {self.category}\n"
            f"SEVERITY: {self.severity}\n"
            f"MESH CONFIDENCE: {self.confidence:.3f}\n"
            f"CAMPAIGN ID: {self.campaign_id or 'None (Isolated Incident)'}\n"
            f"SOURCE IP: {self.source_ip or self.raw_log_details.get('source_ip', 'Unknown')}\n"
            f"TARGET SERVICE: {self.destination_service or self.raw_log_details.get('target_service', 'Unknown')}\n"
            f"AFFECTED ENDPOINTS: {', '.join(self.affected_endpoints) if self.affected_endpoints else 'None specified'}\n"
            f"AFFECTED ENTITIES: {', '.join(self.affected_entities) if self.affected_entities else 'None specified'}\n\n"
            f"CONTRIBUTING DETECTION BRANCH SCORES:\n{scores_str}\n\n"
            f"RAW TELEMETRY / LOG DETAILS:\n{raw_logs_str}\n\n"
            f"TIMELINE OF LINKED EVENTS:\n{timeline_str}\n"
        )
