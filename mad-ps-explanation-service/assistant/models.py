"""
Data models and schemas for MADDY (Multi-Agent Dialogue & Defense Yield) Conversational Assistant.
Supports proactive incident alerting (Task L5), in-chat decision authorization (Task L5),
and transparent grounding evidence panels (Task L6).
"""

from __future__ import annotations

import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from grounding.models import GroundingCitation, GroundingContext


class AssistantIntentType(str, Enum):
    INCIDENT_SPECIFIC = "INCIDENT_SPECIFIC"
    AGGREGATE_STATS = "AGGREGATE_STATS"
    SYSTEM_HEALTH = "SYSTEM_HEALTH"
    MODEL_PERFORMANCE = "MODEL_PERFORMANCE"
    GENERAL_EXPLAINER = "GENERAL_EXPLAINER"
    COMMAND_EXECUTION = "COMMAND_EXECUTION"


class ActionCommand(BaseModel):
    """Autonomous platform action command emitted by MADDY to control UI or execute operations."""
    action: str = Field(..., description="'NAVIGATE_TAB' | 'EXECUTE_INSPECTION' | 'CONVENE_COUNCIL' | 'AUTHORIZE_ACTION' | 'QUERY_DBMS' | 'REFRESH_TOPOLOGY' | 'EXPORT_DATA'")
    target: Optional[str] = None
    payload: Optional[Dict[str, Any]] = None
    parameters: Optional[Dict[str, Any]] = None
    status: str = "PENDING_EXECUTION"


class InlineIncidentCard(BaseModel):
    """Metadata for frontend interactive clickable incident cards."""
    incident_id: str
    category: str
    severity: str
    risk_score: Optional[float] = None
    executive_summary: Optional[str] = None


class PendingActionItem(BaseModel):
    """Remediation or containment action requiring human approval (Task L5)."""
    action_id: str
    priority: str
    category: str
    title: str
    description: str
    target_component: str
    estimated_impact: Optional[str] = None
    requires_human_approval: bool = True
    approval_reasoning: Optional[str] = None
    status: str = "PENDING_APPROVAL"  # 'PENDING_APPROVAL' | 'APPROVED' | 'REJECTED'


class DecisionSubmission(BaseModel):
    """Analyst action authorization payload submitted via chat (Task L5)."""
    incident_id: str
    report_id: str
    action_id: str
    decision: str = Field(..., description="'APPROVE' | 'REJECT' | 'MODIFY'")
    analyst_id: str = "soc_analyst_1"
    comments: Optional[str] = None
    modification_details: Optional[str] = None
    org_id: str = "org_default"


class ProactiveAlertPayload(BaseModel):
    """Proactive event-driven alert emitted by MADDY on HIGH/CRITICAL incidents (Task L5)."""
    type: str = "proactive_notification"
    incident_id: str
    report_id: str
    category: str
    severity: str
    risk_score: float
    message: str
    inline_incidents: List[InlineIncidentCard] = Field(default_factory=list)
    pending_actions: List[PendingActionItem] = Field(default_factory=list)
    requires_human_approval: bool = False
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())


class AssistantQuery(BaseModel):
    """User query payload for MADDY."""
    query: str
    conversation_id: Optional[str] = None
    user_id: str = "soc_analyst_1"
    org_id: str = "org_default"


class AssistantStreamEvent(BaseModel):
    """Event emitted during token streaming over WebSocket."""
    type: str = Field(description="'intent_classified' | 'retrieval_complete' | 'token' | 'done' | 'proactive_notification' | 'decision_recorded' | 'action_triggered' | 'error'")
    conversation_id: Optional[str] = None
    message_id: Optional[str] = None
    token: Optional[str] = None
    intents: Optional[List[AssistantIntentType]] = None
    sources_cited: Optional[List[GroundingCitation]] = None
    inline_incidents: Optional[List[InlineIncidentCard]] = None
    pending_actions: Optional[List[PendingActionItem]] = None
    action_command: Optional[ActionCommand] = None
    proactive_payload: Optional[ProactiveAlertPayload] = None
    full_text: Optional[str] = None
    provider_used: Optional[str] = None
    model_used: Optional[str] = None
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())


class AssistantResponse(BaseModel):
    """Synchronous REST response for MADDY chat."""
    conversation_id: str
    message_id: str
    query: str
    answer: str
    intents: List[AssistantIntentType]
    is_grounded: bool
    sources_cited: List[GroundingCitation]
    inline_incidents: List[InlineIncidentCard]
    pending_actions: List[PendingActionItem] = Field(default_factory=list)
    action_command: Optional[ActionCommand] = None
    provider_used: Optional[str] = None
    model_used: Optional[str] = None
    created_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())

