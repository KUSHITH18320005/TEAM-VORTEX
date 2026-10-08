"""
Pydantic schemas for Human Decisions and Action Authorizations (Task E2).
"""

from __future__ import annotations

import datetime
from enum import Enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class DecisionType(str, Enum):
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    MODIFIED = "MODIFIED"


class ActionDecision(BaseModel):
    """Record of a human analyst decision on a recommended mitigation action."""
    decision_id: str
    incident_id: str
    report_id: str
    action_id: str
    decision: DecisionType
    analyst_id: str = "soc_lead"
    action_title: str
    target_component: str
    priority: str
    comments: Optional[str] = None
    modification_details: Optional[str] = None
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    execution_triggered: bool = False
    execution_status: str = Field(default="PENDING_INTEGRATION", description="Status of downstream mesh action execution")
