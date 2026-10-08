"""
Pydantic schemas for Browser Council v2: 7-Model Panel Debate + Judge (Tasks Y2 - Y9).
Supports 3 Reconstruction Panelists (Round 1), 3 Response Panelists (Round 2),
Cross-Examinations (Task Y5), Judicial Fact-Check Audits (Task Y6), and Fast/Deep Lanes (Task Y8).
"""

from __future__ import annotations

import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AgentRole(str, Enum):
    RECONSTRUCTION = "reconstruction_agent"
    RESPONSE = "response_agent"
    JUDGE = "judge_agent"
    PANELIST = "panelist_agent"


class PanelistRoleType(str, Enum):
    RECONSTRUCTION = "RECONSTRUCTION"  # Panelists 1-3
    RESPONSE = "RESPONSE"              # Panelists 4-6
    JUDGE = "JUDGE"                    # Panelist 7 (Chief Magistrate)


class DebateStance(str, Enum):
    AGREE = "AGREE"
    REVISE = "REVISE"
    DISSENT = "DISSENT"


class ActionPriority(str, Enum):
    P0_IMMEDIATE = "P0_IMMEDIATE"
    P1_HIGH = "P1_HIGH"
    P2_MEDIUM = "P2_MEDIUM"
    P3_LOW = "P3_LOW"


class RecommendedAction(BaseModel):
    """Individual containment or architectural remediation action."""
    action_id: str
    priority: ActionPriority
    category: str = Field(..., description="CONTAINMENT or ARCHITECTURAL_PREVENTION")
    title: str
    description: str
    target_component: str
    estimated_impact: str
    requires_human_approval: bool = False
    approval_reasoning: Optional[str] = None


# ──────────────────────────────────────────────────────────────────────────────
# Browser Council v2: 7-Model Panel Schemas (Tasks Y2 - Y6)
# ──────────────────────────────────────────────────────────────────────────────

class PanelistConfig(BaseModel):
    """Configuration for an independent LLM panelist in Browser Council v2."""
    id: str
    name: str
    title: str
    role_specialty: str
    role_type: PanelistRoleType = PanelistRoleType.RECONSTRUCTION
    provider: str
    model_name: str
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    temperature: float = 0.2
    max_tokens: int = 2048
    weight: float = 1.0
    enabled: bool = True
    avatar_color: str = "#00f2fe"
    badge_label: str = "PANELIST"


class PanelistDeliberation(BaseModel):
    """Independent output produced by a panelist (Round 1 Reconstruction or Round 2 Response)."""
    panelist_id: str
    panelist_name: str
    role_specialty: str
    role_type: PanelistRoleType = PanelistRoleType.RECONSTRUCTION
    model_provider: str
    entry_point: str = Field(..., description="Opening vector directly identified from raw telemetry")
    root_cause_hypothesis: str = Field(..., description="Panelist's root cause and vulnerability analysis")
    severity_assessment: str = Field(..., description="CRITICAL, HIGH, MEDIUM, LOW")
    confidence: float = Field(..., ge=0.0, le=1.0)
    containment_tactics: List[str] = Field(default_factory=list)
    architectural_fixes: List[str] = Field(default_factory=list)
    attack_sequence: List[str] = Field(default_factory=list)
    grounded_evidence: List[str] = Field(default_factory=list)
    requires_human_approval: bool = False
    approval_reasoning: Optional[str] = None
    raw_response: str = Field("", description="Full LLM output")
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())


class CrossExaminationResponse(BaseModel):
    """Formal cross-examination review of peer panelists' outputs (Task Y5)."""
    critique_id: str
    panelist_id: str
    panelist_name: str
    model_provider: str
    target_peer_id: str
    target_peer_name: str
    stance: DebateStance = Field(..., description="AGREE, REVISE, or DISSENT")
    critique_type: str = Field("CHALLENGE", description="ENDORSE, CHALLENGE, AMEND")
    debate_argument: str = Field(..., description="Direct critique or defense against peer conclusion")
    revised_points: List[str] = Field(default_factory=list)
    suggested_amendment: Optional[str] = None


class PeerCritique(BaseModel):
    """Backward-compatible alias for cross-examination critique."""
    critique_id: str
    critic_id: str
    critic_name: str
    target_panelist_id: str
    target_panelist_name: str
    critique_type: str = Field(..., description="ENDORSE, CHALLENGE, EXPAND")
    critique_text: str
    suggested_amendment: Optional[str] = None


class FactCheckFinding(BaseModel):
    """Magistrate fact-check finding auditing a panelist's assertion against raw telemetry (Task Y6.2)."""
    check_id: str
    panelist_id: str
    panelist_name: str
    claim_statement: str
    is_verified_by_telemetry: bool
    grounded_evidence_source: str
    fact_check_verdict: str = Field(..., description="VERIFIED_ACCURATE, UNGROUNDED_CLAIM, or DISCREPANCY_FLAGGED")
    discrepancy_explanation: Optional[str] = None


class PanelistVote(BaseModel):
    """Stance and revision vote cast by a panelist on the Judge's synthesis."""
    panelist_id: str
    panelist_name: str
    model_provider: str
    stance: DebateStance
    rationale: str
    suggested_revisions: List[str] = Field(default_factory=list)
    confidence: float = 0.9


# ──────────────────────────────────────────────────────────────────────────────
# Legacy 3-Agent Backward Compatibility Schemas
# ──────────────────────────────────────────────────────────────────────────────

class ReconstructionResult(BaseModel):
    """Output from Agent 1: Reconstruction Agent."""
    incident_id: str
    entry_point: str = Field(..., description="Opening vector / entry point of attack directly identified from raw telemetry")
    attack_sequence: List[str] = Field(..., description="Chronological sequence of attacker actions grounded strictly in evidence")
    underlying_condition: str = Field(..., description="Root vulnerability / architectural flaw that enabled the attack")
    grounded_evidence_fields: List[str] = Field(default_factory=list, description="List of specific fields from the incident record that ground this analysis")
    raw_response: str = Field("", description="Full unstructured LLM output")
    model_provider: str = Field("", description="Model and provider name used")


class ResponsePlan(BaseModel):
    """Output from Agent 2: Response Agent."""
    incident_id: str
    immediate_containment: List[str] = Field(..., description="Immediate tactical containment actions")
    architectural_prevention: List[str] = Field(..., description="System-design-level prevention recommendations")
    requires_human_approval: bool = Field(..., description="Whether automated execution must be paused for human authorization")
    human_approval_reasoning: str = Field(..., description="Detailed explanation of why human sign-off is or is not required")
    actions: List[RecommendedAction] = Field(default_factory=list)
    raw_response: str = Field("", description="Full unstructured LLM output")
    model_provider: str = Field("", description="Model and provider name used")


class JudgeSynthesis(BaseModel):
    """Output from Magistrate Judge: Judicial Synthesis Agent (Task Y6)."""
    incident_id: str
    factuality_grounding_audit: str = Field(..., description="Evaluation of whether arguments stay grounded in raw data")
    proportionality_audit: str = Field(..., description="Evaluation of whether proposed responses are proportionate")
    executive_summary: str = Field(..., description="Clear C-suite / SOC lead summary of the incident")
    technical_timeline: List[str] = Field(..., description="Unified technical sequence of events")
    root_cause_analysis: str = Field(..., description="Synthesized root cause analysis")
    ranked_actions: List[RecommendedAction] = Field(..., description="Final ranked actions with priority and approval flags")
    requires_human_approval: bool = Field(..., description="Unified human decision flag carried through with justification")
    human_approval_justification: str
    fact_check_findings: List[FactCheckFinding] = Field(default_factory=list, description="Explicit verification / hallucination-catch audit (Task Y6.2)")
    panel_consensus_score: float = Field(default=100.0, description="0.0 to 100.0% consensus score (Task Y6.4)")
    consensus_status: str = Field(default="FULL_CONSENSUS", description="FULL_CONSENSUS, STRONG_CONSENSUS, SPLIT_PANEL, DISSENT")
    unresolved_disagreements: List[str] = Field(default_factory=list, description="Explicit points of dispute between panelists")
    raw_response: str = Field("", description="Full unstructured LLM output")
    model_provider: str = Field("", description="Model and provider name used")


class RevisionFeedback(BaseModel):
    """Debate revision response after reviewing the Judge's synthesis."""
    agent_role: AgentRole
    model_provider: str
    stance: DebateStance = Field(..., description="AGREE, REVISE, or DISSENT")
    rationale: str = Field(..., description="Why the agent agrees, revises, or dissents from the judge's assessment")
    revised_points: List[str] = Field(default_factory=list, description="Specific amendments or counter-arguments")
    raw_response: str = Field("", description="Full unstructured LLM output")


class ConsensusMetric(BaseModel):
    """Consensus score and breakdown across debating panelists."""
    status: str = Field(..., description="FULL_CONSENSUS, STRONG_CONSENSUS, PARTIAL_CONSENSUS, DISSENT")
    consensus_score: float = Field(..., ge=0.0, le=1.0, description="Confidence via consensus score from 0.0 to 1.0")
    agree_count: int
    revise_count: int
    dissent_count: int
    total_panelists: int = 7
    notes: str


from .risk import RiskAssessment
from .timeline import GroundedTimeline


class FinalExplanationReport(BaseModel):
    """Final unified incident explanation report produced by the multi-model council."""
    report_id: str
    incident_id: str
    org_id: Optional[str] = Field(default="org_default", description="Organization ID owning the incident")
    surface_id: Optional[str] = Field(default=None, description="Monitored surface ID where incident originated")
    surface_name: Optional[str] = Field(default=None, description="Monitored surface display name")
    generated_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    execution_lane: str = Field(default="DEEP_LANE", description="FAST_LANE (single model) or DEEP_LANE (7-model panel)")
    executive_summary: str
    incident_category: str
    detection_mesh_confidence: float
    consensus_metric: ConsensusMetric
    panel_consensus_score: float = Field(default=100.0, description="Computed 0.0 - 100.0% consensus score")
    requires_human_approval: bool
    human_approval_reasoning: str
    root_cause: str
    technical_timeline: List[str]
    reconstruction_findings: Optional[ReconstructionResult] = None
    response_plan: Optional[ResponsePlan] = None
    judge_synthesis: JudgeSynthesis
    debate_revisions: List[RevisionFeedback] = Field(default_factory=list)
    ranked_actions: List[RecommendedAction]
    round1_reconstructions: List[PanelistDeliberation] = Field(default_factory=list)
    round2_responses: List[PanelistDeliberation] = Field(default_factory=list)
    cross_examinations: List[CrossExaminationResponse] = Field(default_factory=list)
    panel_deliberations: List[PanelistDeliberation] = Field(default_factory=list)
    peer_critiques: List[PeerCritique] = Field(default_factory=list)
    panel_votes: List[PanelistVote] = Field(default_factory=list)
    participating_models: Dict[str, str] = Field(
        default_factory=dict,
        description="Map of panelist IDs and Judge to model provider signatures",
    )
    risk_assessment: Optional[RiskAssessment] = Field(
        default=None,
        description="Deterministic mathematical risk assessment (Task D1)",
    )
    grounded_timeline: Optional[GroundedTimeline] = Field(
        default=None,
        description="Telemetry-grounded chronological event timeline with LLM narration (Task D2)",
    )
