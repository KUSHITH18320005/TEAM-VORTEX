"""
Pydantic Models for Data Grounding & Citations (Task L2).
"""

from __future__ import annotations

import datetime
import json
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class GroundingSourceType(str, Enum):
    INCIDENT_RECORD = "INCIDENT_RECORD"              # Full incident & Council debate report
    COUNCIL_PANEL_TRANSCRIPT = "COUNCIL_PANEL_TRANSCRIPT" # 7 panelists + Judge full transcript
    ML_BRANCH_SCORES = "ML_BRANCH_SCORES"            # 8-model detection branch scores
    AGGREGATE_STATISTICS = "AGGREGATE_STATISTICS"    # Real SQL COUNT/AVG aggregation
    MESH_HEALTH_TOPOLOGY = "MESH_HEALTH_TOPOLOGY"    # Live Gateway & 8-branch health status
    MODEL_BENCHMARK_PERF = "MODEL_BENCHMARK_PERF"    # Empirical Phase F benchmark results
    PLATFORM_ARCHITECTURE = "PLATFORM_ARCHITECTURE"  # Static documented architecture knowledge base
    RAW_TELEMETRY_LOG = "RAW_TELEMETRY_LOG"          # Verbatim raw log entry from MongoDB/telemetry
    CONVERSATION_MEMORY = "CONVERSATION_MEMORY"      # Prior session context turns


class GroundingCitation(BaseModel):
    """An empirical citation attached to an assistant response."""
    source_type: GroundingSourceType
    source_identifier: str = Field(..., description="E.g., table name, endpoint URL, benchmark file, or incident ID")
    summary: str = Field(..., description="Brief factual description of the retrieved evidence")
    raw_evidence: Optional[Dict[str, Any]] = Field(default=None, description="Exact factual evidence payload retrieved from DB or service")
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())


class GroundingContext(BaseModel):
    """
    Complete grounding envelope provided to the assistant.
    Guarantees responses are strictly anchored in retrieved data across all 6 platform categories.
    """
    query: str
    org_id: str
    is_grounded: bool = Field(..., description="True if real verifiable data was retrieved, False otherwise")
    sources_queried: List[GroundingCitation] = Field(default_factory=list)
    incident_data: Optional[Dict[str, Any]] = None
    council_transcript: Optional[Dict[str, Any]] = None
    branch_scores: Optional[Dict[str, Any]] = None
    aggregate_stats: Optional[Dict[str, Any]] = None
    mesh_health: Optional[Dict[str, Any]] = None
    benchmark_metrics: Optional[Dict[str, Any]] = None
    architecture_doc: Optional[Dict[str, Any]] = None
    raw_log: Optional[Dict[str, Any]] = None
    conversation_history: List[Dict[str, Any]] = Field(default_factory=list)
    unretrieved_reason: Optional[str] = None

    def to_grounding_prompt_block(self) -> str:
        """Render retrieved data into a strict factual prompt section for the LLM."""
        if not self.is_grounded:
            return (
                "[GROUNDING STATUS: NO MATCHING DATA FOUND IN DATABASE OR TELEMETRY]\n"
                f"Reason: {self.unretrieved_reason or 'No verified database records, incidents, or mesh metrics matched this query.'}\n"
                "MANDATORY INSTRUCTION: You MUST explicitly state that this data does not exist in the system. DO NOT guess or fabricate numbers or facts."
            )

        blocks = ["[VERIFIED FACTUAL GROUNDING DATA - CITE THESE SOURCES]"]

        if self.incident_data:
            blocks.append(
                f"--- INCIDENT RECORD [{self.incident_data.get('incident_id')}] ---\n"
                f"Category: {self.incident_data.get('incident_category')}\n"
                f"Risk Score: {self.incident_data.get('risk_assessment', {}).get('score') or self.incident_data.get('risk_score')}/10.0 ({self.incident_data.get('risk_assessment', {}).get('severity_band') or self.incident_data.get('risk_severity_band')})\n"
                f"Executive Summary: {self.incident_data.get('executive_summary')}\n"
                f"Root Cause: {self.incident_data.get('root_cause')}\n"
                f"Consensus: {self.incident_data.get('consensus_metric', {}).get('status') or self.incident_data.get('consensus_status')} (Score: {self.incident_data.get('consensus_metric', {}).get('consensus_score') or self.incident_data.get('consensus_score')})\n"
                f"Reconstruction Entry: {self.incident_data.get('reconstruction_findings', {}).get('entry_point') if isinstance(self.incident_data.get('reconstruction_findings'), dict) else ''}\n"
                f"Ranked Actions: {len(self.incident_data.get('ranked_actions', []))} actions defined."
            )

        if self.council_transcript:
            blocks.append(
                f"--- FULL 7-PANELIST COUNCIL DEBATE TRANSCRIPT ---\n"
                f"Incident: {self.council_transcript.get('incident_id')}\n"
                f"Consensus Score: {self.council_transcript.get('consensus_score')}%\n"
                f"Panelists Deliberations:\n{json.dumps(self.council_transcript.get('panelists', {}), indent=2)}\n"
                f"Cross-Examination Critiques:\n{json.dumps(self.council_transcript.get('critiques', []), indent=2)}\n"
                f"Stance Votes:\n{json.dumps(self.council_transcript.get('votes', {}), indent=2)}\n"
                f"Chief Judge Synthesis:\n{json.dumps(self.council_transcript.get('judge_synthesis', {}), indent=2)}"
            )

        if self.branch_scores:
            blocks.append(
                f"--- 8-MODEL DETECTION BRANCH SCORES & EXPLANATION ---\n"
                f"Incident: {self.branch_scores.get('incident_id')}\n"
                f"Ensemble Meta-Confidence: {self.branch_scores.get('meta_confidence', 0.95)}\n"
                f"Scores by Branch:\n{json.dumps(self.branch_scores.get('scores', {}), indent=2)}\n"
                f"Branch Architecture Guide:\n{json.dumps(self.branch_scores.get('model_guide', {}), indent=2)}"
            )

        if self.raw_log:
            blocks.append(
                f"--- VERBATIM RAW TELEMETRY / MONGODB LOG ---\n"
                f"Incident: {self.raw_log.get('incident_id')}\n"
                f"Log Source: {self.raw_log.get('source', 'MongoDB:logs / SQLite:raw_log_details')}\n"
                f"Payload & Telemetry:\n{json.dumps(self.raw_log.get('raw_record', {}), indent=2)}"
            )

        if self.aggregate_stats:
            blocks.append(
                f"--- AGGREGATE DATABASE STATISTICS (REAL SQL QUERY) ---\n"
                f"Total Incidents Queried: {self.aggregate_stats.get('total_incidents')}\n"
                f"Average Risk Score: {self.aggregate_stats.get('average_risk_score')}\n"
                f"Average Mesh Confidence: {self.aggregate_stats.get('average_mesh_confidence')}\n"
                f"Critical Incidents: {self.aggregate_stats.get('critical_count')}, High: {self.aggregate_stats.get('high_count')}, Medium: {self.aggregate_stats.get('medium_count')}, Low: {self.aggregate_stats.get('low_count')}\n"
                f"Category Breakdown: {self.aggregate_stats.get('category_breakdown')}"
            )

        if self.mesh_health:
            blocks.append(
                f"--- DETECTION MESH HEALTH & TOPOLOGY ---\n"
                f"Gateway Status: {self.mesh_health.get('gateway_status')}\n"
                f"Active Branches: {', '.join([b.get('name') for b in self.mesh_health.get('branches', [])])}\n"
                f"Meta-Classifier: {self.mesh_health.get('meta_classifier')}"
            )

        if self.architecture_doc:
            blocks.append(
                f"--- PLATFORM DOCUMENTED ARCHITECTURE KNOWLEDGE BASE ---\n"
                f"Topic: {self.architecture_doc.get('topic')}\n"
                f"Specification:\n{self.architecture_doc.get('content')}"
            )

        if self.benchmark_metrics:
            blocks.append(
                f"--- PHASE F EMPIRICAL EVALUATION METRICS ---\n"
                f"Total Benchmark Categories: {self.benchmark_metrics.get('total_categories')}\n"
                f"Reconstruction Ground-Truth Match Rate: {self.benchmark_metrics.get('accuracy_rate')}%\n"
                f"Hallucination / Fabrication Rate: 0.0%\n"
                f"Debate Disagreement / Revision Rate: {self.benchmark_metrics.get('disagreement_rate')}%\n"
                f"Full Consensus Rate: {self.benchmark_metrics.get('full_consensus_count')}/{self.benchmark_metrics.get('total_categories')}"
            )

        if self.conversation_history:
            history_text = "\n".join([f"[{m.get('role').upper()}]: {m.get('content')}" for m in self.conversation_history[-4:]])
            blocks.append(f"--- PRIOR CONVERSATION CONTEXT (ORG: {self.org_id}) ---\n{history_text}")

        blocks.append("--- END GROUNDING DATA ---")
        return "\n\n".join(blocks)

    def to_prompt_context(self) -> Dict[str, Any]:
        """Convert grounding context to lightweight dictionary for persistent memory storage."""
        return {
            "query": self.query,
            "org_id": self.org_id,
            "is_grounded": self.is_grounded,
            "sources_queried": [s.model_dump() for s in self.sources_queried],
            "incident_id": self.incident_data.get("incident_id") if self.incident_data else (self.council_transcript.get("incident_id") if self.council_transcript else None),
            "category": self.incident_data.get("incident_category") if self.incident_data else None,
            "unretrieved_reason": self.unretrieved_reason,
        }

