"""
Multi-Agent Council Debate Engine for Browser Council v2 (7-Model Panel Debate + Judge).
Coordinates a 7-Model Multi-Expert Panel across distinct LLM providers (Anthropic Claude 3.5 Sonnet,
OpenAI GPT-4o, Google Gemini 2.0 Flash, Groq Llama 3.3 70B, Groq Mixtral 8x7B, DeepSeek Chat, and
Magistrate Judge), peer cross-examinations, telemetry fact-checking audits, and Fast/Deep Lane gating.
"""

from __future__ import annotations

import asyncio
import datetime
import json
import logging
import re
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple

from distillation.models import DebateTranscript
from distillation.pipeline import DistillationPipeline
from llm.base import BaseLLMProvider
from llm.config_manager import llm_config_manager
from schemas.incident import IncidentRecord
from schemas.report import (
    ActionPriority,
    AgentRole,
    ConsensusMetric,
    CrossExaminationResponse,
    DebateStance,
    FactCheckFinding,
    FinalExplanationReport,
    JudgeSynthesis,
    PanelistConfig,
    PanelistDeliberation,
    PanelistRoleType,
    PanelistVote,
    PeerCritique,
    RecommendedAction,
    ReconstructionResult,
    ResponsePlan,
    RevisionFeedback,
)
from scoring.risk_calculator import RiskCalculator
from streaming.broadcast import CouncilBroadcaster
from timeline.correlator import TimelineCorrelator

from .judge_agent import JudgeAgent
from .panelist_agent import PanelistAgent
from .reconstruction_agent import ReconstructionAgent
from .response_agent import ResponseAgent

logger = logging.getLogger("mad_ps_explanation.agents.council")


class CouncilDebateEngine:
    """
    Browser Council v2 Multi-Model Debate Engine:
    - Task Y8: Fast-Lane (<0.70 confidence or <7.0 risk) vs Deep-Lane (≥0.70 confidence & ≥7.0 risk) Gating
    - Task Y2: Unified Shared Grounding Context across all panelists
    - Task Y3: Round 1 Reconstruction (Panelists 1-3: Forensics, Threat Intel, Exploit Analysis)
    - Task Y4: Round 2 Response (Panelists 4-6: Fast Mitigation, Resilience, Compliance)
    - Task Y5: Round 3 Peer Cross-Examinations (Panelists 1-6)
    - Task Y6: Round 4 Chief Magistrate Judicial Fact-Check Audit & Synthesis
    - Round 5: Panelist Stance Voting & Mathematical Consensus Metric
    """

    def __init__(
        self,
        broadcaster: Optional[CouncilBroadcaster] = None,
        distillation_pipeline: Optional[DistillationPipeline] = None,
        force_mock: bool = False,
        reconstruction_provider: Optional[BaseLLMProvider] = None,
        response_provider: Optional[BaseLLMProvider] = None,
        judge_provider: Optional[BaseLLMProvider] = None,
        **kwargs: Any,
    ) -> None:
        self.broadcaster = broadcaster or CouncilBroadcaster()
        self.distillation_pipeline = distillation_pipeline or DistillationPipeline()

        # Initialize Judge Agent
        jp = judge_provider or llm_config_manager.get_judge_provider()
        self.judge_agent = JudgeAgent(jp)

        # Legacy backward-compatibility agents
        p1, p2, _ = llm_config_manager.get_council_providers()
        self.reconstruction_agent = ReconstructionAgent(reconstruction_provider or p1)
        self.response_agent = ResponseAgent(response_provider or p2)

        self.custom_recon_p = reconstruction_provider
        self.custom_resp_p = response_provider
        self.custom_judge_p = judge_provider

    def _calculate_consensus(self, revisions: List[RevisionFeedback]) -> ConsensusMetric:
        """Calculate weighted consensus metric across revisions for backward compatibility."""
        total = len(revisions) or 2
        agree_count = sum(1 for r in revisions if r.stance == DebateStance.AGREE)
        revise_count = sum(1 for r in revisions if r.stance == DebateStance.REVISE)
        dissent_count = sum(1 for r in revisions if r.stance == DebateStance.DISSENT)

        score = (agree_count * 1.0 + revise_count * 0.76 + dissent_count * 0.0) / total
        score = round(min(1.0, max(0.0, score)), 2)

        if dissent_count > 0 or score < 0.60:
            status = "DISSENT"
        elif score >= 0.95:
            status = "FULL_CONSENSUS"
        elif score >= 0.75:
            status = "STRONG_CONSENSUS"
        else:
            status = "PARTIAL_CONSENSUS"

        return ConsensusMetric(
            status=status,
            consensus_score=score,
            agree_count=agree_count,
            revise_count=revise_count,
            dissent_count=dissent_count,
            total_panelists=total,
            notes=f"{agree_count}/{total} agreed, {revise_count} revised, {dissent_count} dissented",
        )

    @property
    def model_signatures(self) -> Dict[str, str]:
        """Return provider signatures for active panelists and Judge."""
        panelists = self._get_active_panelists()
        sigs = {p.panelist_id: f"{p.name} ({p.llm_provider.display_name})" for p in panelists}
        sigs["judge_magistrate"] = f"The Arbiter ({self.judge_agent.llm_provider.display_name})"
        return sigs

    def _get_active_panelists(self) -> List[PanelistAgent]:
        """Instantiate PanelistAgent instances for all enabled panelists from config."""
        panelist_configs = llm_config_manager.get_council_panelist_configs()
        agents: List[PanelistAgent] = []
        for idx, cfg in enumerate(panelist_configs):
            if cfg.enabled:
                if idx == 0 and self.custom_recon_p:
                    provider = self.custom_recon_p
                elif idx == 3 and self.custom_resp_p:
                    provider = self.custom_resp_p
                else:
                    provider = llm_config_manager.get_panelist_provider(cfg)
                agents.append(PanelistAgent(config=cfg, provider=provider))
        return agents

    async def run_council_debate(
        self,
        incident: IncidentRecord,
        supplemental_logs: Optional[List[Dict[str, Any]]] = None,
        force_deep_lane: bool = False,
    ) -> FinalExplanationReport:
        """Route to Fast-Lane Summary or Deep-Lane 7-Model Debate and return unified report."""
        session_id = f"council-{uuid.uuid4().hex[:8]}"
        risk_assessment = RiskCalculator.calculate_risk(incident)
        logger.info(
            "[Council v2 %s] Incident %s (%s) | Confidence: %.2f | Risk Score: %.2f (%s)",
            session_id,
            incident.incident_id,
            incident.category,
            incident.confidence,
            risk_assessment.score,
            risk_assessment.severity_band,
        )

        # ══════════════════════════════════════════════════════════════════
        # Task Y8: Fast-Lane vs Deep-Lane Threshold Gating
        # Fast-Lane: confidence < 0.70 OR risk < 7.0
        # Deep-Lane: confidence >= 0.70 AND risk >= 7.0
        # ══════════════════════════════════════════════════════════════════
        is_deep_lane = force_deep_lane or (incident.confidence >= 0.70 and risk_assessment.score >= 7.0)

        if not is_deep_lane:
            logger.info("[Council v2 %s] Routing to FAST-LANE (Routine Severity / Confidence Gated)", session_id)
            return await self._run_fast_lane_summary(incident, risk_assessment, session_id, supplemental_logs)

        logger.info("[Council v2 %s] Routing to DEEP-LANE (7-Model Multi-Round Panel Debate)", session_id)
        return await self._run_deep_lane_panel(incident, risk_assessment, session_id, supplemental_logs)

    # ──────────────────────────────────────────────────────────────────────────
    # Fast-Lane: Single Judge Magistrate Summary (Task Y8)
    # ──────────────────────────────────────────────────────────────────────────
    async def _run_fast_lane_summary(
        self,
        incident: IncidentRecord,
        risk_assessment: Any,
        session_id: str,
        supplemental_logs: Optional[List[Dict[str, Any]]] = None,
    ) -> FinalExplanationReport:
        """Execute Fast-Lane Magistrate summary for low/medium risk incidents."""
        await self.broadcaster.phase_announce(
            f"⚡ Fast-Lane Activated: Incident {incident.incident_id} ({incident.category}) routed to Single-Model Magistrate Summary (< 7.0 Risk / < 0.70 Confidence)...",
            phase="phase_3_synthesis",
        )

        judge_stream_cb = self.broadcaster.create_stream_callback(
            source=AgentRole.JUDGE.value,
            phase="phase_3_synthesis",
        )

        judge_synthesis = await self.judge_agent.synthesize(
            incident=incident,
            stream_callback=judge_stream_cb,
        )

        await self.broadcaster.broadcast(
            event_type="agent_response",
            source=AgentRole.JUDGE.value,
            text=f"Fast-Lane Magistrate Summary:\n{judge_synthesis.executive_summary}\nRanked Actions: {len(judge_synthesis.ranked_actions)}",
            phase="phase_3_synthesis",
            extra={"result": judge_synthesis.model_dump()},
        )

        # Backward compatibility synthesis
        entry_pt = incident.raw_log_details.get("endpoint") or (incident.affected_endpoints[0] if incident.affected_endpoints else "/")
        valid_ev = [f"endpoint: {entry_pt}", f"category: {incident.category}"]
        if incident.source_ip:
            valid_ev.append(f"source_ip: {incident.source_ip}")

        recon_result = ReconstructionResult(
            incident_id=incident.incident_id,
            entry_point=entry_pt,
            attack_sequence=judge_synthesis.technical_timeline,
            underlying_condition=judge_synthesis.root_cause_analysis,
            grounded_evidence_fields=valid_ev,
            raw_response=judge_synthesis.raw_response,
            model_provider=judge_synthesis.model_provider,
        )

        response_plan = ResponsePlan(
            incident_id=incident.incident_id,
            immediate_containment=[a.title for a in judge_synthesis.ranked_actions if a.category == "CONTAINMENT"] or ["Isolate attacker session"],
            architectural_prevention=[a.title for a in judge_synthesis.ranked_actions if a.category == "ARCHITECTURAL_PREVENTION"] or ["Deploy AST boundary validation"],
            requires_human_approval=judge_synthesis.requires_human_approval,
            human_approval_reasoning=judge_synthesis.human_approval_justification,
            actions=judge_synthesis.ranked_actions,
            raw_response="",
            model_provider=judge_synthesis.model_provider,
        )

        legacy_revisions: List[RevisionFeedback] = [
            RevisionFeedback(
                agent_role=AgentRole.RECONSTRUCTION,
                model_provider=judge_synthesis.model_provider,
                stance=DebateStance.AGREE,
                rationale="Fast-Lane magistrate reconstruction verified.",
                revised_points=[],
                raw_response=judge_synthesis.raw_response,
            ),
            RevisionFeedback(
                agent_role=AgentRole.RESPONSE,
                model_provider=judge_synthesis.model_provider,
                stance=DebateStance.AGREE,
                rationale="Fast-Lane magistrate response plan confirmed.",
                revised_points=[],
                raw_response="",
            ),
        ]

        # Build timeline
        grounded_timeline = None
        try:
            grounded_timeline = TimelineCorrelator.build_grounded_timeline(
                incident=incident,
                reconstruction=recon_result,
                supplemental_logs=supplemental_logs,
            )
        except Exception as te:
            logger.debug("Fast-Lane timeline correlation error: %s", te)

        consensus_metric = ConsensusMetric(
            status="FULL_CONSENSUS",
            consensus_score=1.0,
            agree_count=1,
            revise_count=0,
            dissent_count=0,
            total_panelists=1,
            notes="Fast-Lane Single-Model Magistrate execution for low-risk event.",
        )

        report = FinalExplanationReport(
            report_id=f"REP-{incident.incident_id}-{uuid.uuid4().hex[:6]}",
            incident_id=incident.incident_id,
            org_id="org_default",
            generated_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            execution_lane="FAST_LANE",
            executive_summary=judge_synthesis.executive_summary,
            incident_category=incident.category,
            detection_mesh_confidence=incident.confidence,
            consensus_metric=consensus_metric,
            panel_consensus_score=100.0,
            requires_human_approval=judge_synthesis.requires_human_approval,
            human_approval_reasoning=judge_synthesis.human_approval_justification,
            root_cause=judge_synthesis.root_cause_analysis,
            technical_timeline=judge_synthesis.technical_timeline,
            reconstruction_findings=recon_result,
            response_plan=response_plan,
            judge_synthesis=judge_synthesis,
            debate_revisions=legacy_revisions,
            ranked_actions=judge_synthesis.ranked_actions,
            round1_reconstructions=[],
            round2_responses=[],
            cross_examinations=[],
            panel_deliberations=[],
            peer_critiques=[],
            panel_votes=[],
            participating_models={
                "judge_magistrate": f"The Arbiter ({self.judge_agent.llm_provider.display_name})",
                AgentRole.RECONSTRUCTION.value: self.reconstruction_agent.llm_provider.display_name,
                AgentRole.RESPONSE.value: self.response_agent.llm_provider.display_name,
                AgentRole.JUDGE.value: self.judge_agent.llm_provider.display_name,
            },
            risk_assessment=risk_assessment,
            grounded_timeline=grounded_timeline,
        )

        # Record transcript to distillation pipeline
        try:
            transcript = DebateTranscript(
                session_id=session_id,
                incident_id=incident.incident_id,
                category=incident.category,
                incident_record=incident,
                reconstruction_result=recon_result,
                response_plan=response_plan,
                judge_synthesis=judge_synthesis,
                debate_revisions=legacy_revisions,
                consensus_metric=consensus_metric,
                final_report=report,
                quality_score=0.95,
                is_distillation_exemplar=True,
            )
            self.distillation_pipeline.record_transcript(transcript)
        except Exception as dist_exc:
            logger.debug("Distillation pipeline notice: %s", dist_exc)

        await self.broadcaster.phase_announce(
            f"✅ Fast-Lane summary complete for Incident {incident.incident_id}.",
            phase="phase_5_consensus",
        )
        await self.broadcaster.broadcast(
            event_type="debate_complete",
            source="council_engine",
            text=f"Fast-Lane explanation generated for {incident.incident_id}.",
            phase="phase_5_consensus",
            extra={"report": report.model_dump()},
        )
        await self.broadcaster.broadcast(
            event_type="council_complete",
            source="council_engine",
            text=f"Fast-Lane complete for {incident.incident_id}.",
            phase="phase_5_consensus",
            extra={"report": report.model_dump()},
        )
        return report

    # ──────────────────────────────────────────────────────────────────────────
    # Deep-Lane: 7-Model Panel Debate (Tasks Y2 - Y6)
    # ──────────────────────────────────────────────────────────────────────────
    async def _run_deep_lane_panel(
        self,
        incident: IncidentRecord,
        risk_assessment: Any,
        session_id: str,
        supplemental_logs: Optional[List[Dict[str, Any]]] = None,
    ) -> FinalExplanationReport:
        """Execute full 7-Model Panel Debate across 5 sequential rounds."""
        panelists = self._get_active_panelists()

        # Allocate 3 Reconstruction (Panelists 1-3) and 3 Response (Panelists 4-6)
        recon_panelists = [p for p in panelists if p.role_type == PanelistRoleType.RECONSTRUCTION]
        resp_panelists = [p for p in panelists if p.role_type == PanelistRoleType.RESPONSE]

        # Fallback if roles not explicitly populated: split 3 / 3
        if not recon_panelists or not resp_panelists:
            recon_panelists = panelists[:3]
            resp_panelists = panelists[3:]

        participating_models: Dict[str, str] = {}
        for p in panelists:
            participating_models[p.panelist_id] = f"{p.name} ({p.llm_provider.display_name})"
        participating_models["judge_magistrate"] = f"The Arbiter ({self.judge_agent.llm_provider.display_name})"
        participating_models[AgentRole.RECONSTRUCTION.value] = recon_panelists[0].llm_provider.display_name if recon_panelists else "anthropic"
        participating_models[AgentRole.RESPONSE.value] = resp_panelists[0].llm_provider.display_name if resp_panelists else "openai"
        participating_models[AgentRole.JUDGE.value] = self.judge_agent.llm_provider.display_name

        # ──────────────────────────────────────────────────────────────────────
        # Task Y2: Shared Grounding Assembly
        # ──────────────────────────────────────────────────────────────────────
        shared_grounding = incident.to_grounding_context()

        # ──────────────────────────────────────────────────────────────────────
        # Task Y3: Round 1 — Reconstruction (Panelists 1-3 in parallel)
        # ──────────────────────────────────────────────────────────────────────
        await self.broadcaster.phase_announce(
            f"🏛️ Round 1: Reconstruction — Convening Panelists 1-3 ({', '.join(p.name for p in recon_panelists)}) to analyze 'what happened and why' from shared telemetry...",
            phase="phase_1_reconstruction",
        )

        async def run_round1_panelist(panelist: PanelistAgent) -> PanelistDeliberation:
            stream_cb = self.broadcaster.create_stream_callback(
                source=panelist.panelist_id,
                phase="phase_1_reconstruction",
            )
            delib = await panelist.reconstruct(
                incident=incident,
                shared_grounding=shared_grounding,
                stream_callback=stream_cb,
            )
            await self.broadcaster.broadcast(
                event_type="agent_response",
                source=panelist.panelist_id,
                text=f"[{panelist.name} - Round 1 Reconstruction]\nEntry Point: {delib.entry_point}\nRoot Cause: {delib.root_cause_hypothesis}\nSeverity: {delib.severity_assessment} ({delib.confidence * 100:.1f}%)",
                phase="phase_1_reconstruction",
                extra={
                    "panelist": {
                        "id": panelist.panelist_id,
                        "name": panelist.name,
                        "role": panelist.specialty,
                        "role_type": panelist.role_type.value,
                        "avatar_color": panelist.config.avatar_color,
                        "badge": panelist.config.badge_label,
                        "model": panelist.llm_provider.display_name,
                    },
                    "deliberation": delib.model_dump(),
                },
            )
            return delib

        r1_deliberations: List[PanelistDeliberation] = await asyncio.gather(
            *[run_round1_panelist(p) for p in recon_panelists]
        )

        # ──────────────────────────────────────────────────────────────────────
        # Task Y4: Round 2 — Response (Panelists 4-6 seeing Round 1 outputs)
        # ──────────────────────────────────────────────────────────────────────
        await self.broadcaster.phase_announce(
            f"🛡️ Round 2: Response — Convening Panelists 4-6 ({', '.join(p.name for p in resp_panelists)}) with full access to Round 1 reconstructions to formulate containment & architecture...",
            phase="phase_2_response",
        )

        async def run_round2_panelist(panelist: PanelistAgent) -> PanelistDeliberation:
            stream_cb = self.broadcaster.create_stream_callback(
                source=panelist.panelist_id,
                phase="phase_2_response",
            )
            delib = await panelist.respond(
                incident=incident,
                shared_grounding=shared_grounding,
                round1_reconstructions=r1_deliberations,
                stream_callback=stream_cb,
            )
            await self.broadcaster.broadcast(
                event_type="agent_response",
                source=panelist.panelist_id,
                text=f"[{panelist.name} - Round 2 Response]\nContainment: {', '.join(delib.containment_tactics[:2])}\nArchitectural Fixes: {', '.join(delib.architectural_fixes[:2])}\nHuman Approval Required: {delib.requires_human_approval}",
                phase="phase_2_response",
                extra={
                    "panelist": {
                        "id": panelist.panelist_id,
                        "name": panelist.name,
                        "role": panelist.specialty,
                        "role_type": panelist.role_type.value,
                        "avatar_color": panelist.config.avatar_color,
                        "badge": panelist.config.badge_label,
                        "model": panelist.llm_provider.display_name,
                    },
                    "deliberation": delib.model_dump(),
                },
            )
            return delib

        r2_deliberations: List[PanelistDeliberation] = await asyncio.gather(
            *[run_round2_panelist(p) for p in resp_panelists]
        )

        all_deliberations = r1_deliberations + r2_deliberations

        # ──────────────────────────────────────────────────────────────────────
        # Task Y5: Round 3 — Peer Cross-Examinations (Panelists 1-6)
        # ──────────────────────────────────────────────────────────────────────
        await self.broadcaster.phase_announce(
            "⚔️ Round 3: Cross-Examination — Panelists 1-6 cross-examining peer arguments, identifying blind spots, and revising positions...",
            phase="cross_examination",
        )

        async def run_panelist_cx(panelist: PanelistAgent) -> List[CrossExaminationResponse]:
            stream_cb = self.broadcaster.create_stream_callback(
                source=panelist.panelist_id,
                phase="cross_examination",
            )
            cx_responses = await panelist.cross_examine(
                incident=incident,
                shared_grounding=shared_grounding,
                other_panelist_outputs=all_deliberations,
                stream_callback=stream_cb,
            )
            for cx in cx_responses:
                await self.broadcaster.broadcast(
                    event_type="cross_examination",
                    source=panelist.panelist_id,
                    text=f"[{cx.panelist_name} -> {cx.target_peer_name}] ({cx.stance.value}/{cx.critique_type}): {cx.debate_argument}",
                    phase="cross_examination",
                    extra={"cross_examination": cx.model_dump()},
                )
            return cx_responses

        cx_groups = await asyncio.gather(*[run_panelist_cx(p) for p in panelists])
        all_cross_examinations: List[CrossExaminationResponse] = [c for grp in cx_groups for c in grp]

        # Convert to PeerCritique for backward compatibility
        all_peer_critiques: List[PeerCritique] = [
            PeerCritique(
                critique_id=cx.critique_id,
                critic_id=cx.panelist_id,
                critic_name=cx.panelist_name,
                target_panelist_id=cx.target_peer_id,
                target_panelist_name=cx.target_peer_name,
                critique_type=cx.critique_type,
                critique_text=cx.debate_argument,
                suggested_amendment=cx.suggested_amendment,
            )
            for cx in all_cross_examinations
        ]

        # ──────────────────────────────────────────────────────────────────────
        # Task Y6: Round 4 — Chief Magistrate Fact-Checking Audit & Synthesis
        # ──────────────────────────────────────────────────────────────────────
        await self.broadcaster.phase_announce(
            f"⚖️ Round 4: Chief Magistrate ({self.judge_agent.llm_provider.display_name}) auditing telemetry grounding, executing hallucination catches, resolving splits, and synthesizing report...",
            phase="phase_3_synthesis",
        )

        judge_stream_cb = self.broadcaster.create_stream_callback(
            source=AgentRole.JUDGE.value,
            phase="phase_3_synthesis",
        )
        judge_synthesis: JudgeSynthesis = await self.judge_agent.synthesize(
            incident=incident,
            round1_reconstructions=r1_deliberations,
            round2_responses=r2_deliberations,
            cross_examinations=all_cross_examinations,
            panel_deliberations=all_deliberations,
            peer_critiques=all_peer_critiques,
            stream_callback=judge_stream_cb,
        )

        await self.broadcaster.broadcast(
            event_type="agent_response",
            source=AgentRole.JUDGE.value,
            text=f"Magistrate Synthesis:\n{judge_synthesis.executive_summary}\nFact Checks Audited: {len(judge_synthesis.fact_check_findings)}\nConsensus Score: {judge_synthesis.panel_consensus_score:.1f}%",
            phase="phase_3_synthesis",
            extra={"result": judge_synthesis.model_dump()},
        )
        await self.broadcaster.broadcast(
            event_type="council_verdict",
            source=AgentRole.JUDGE.value,
            text=judge_synthesis.executive_summary,
            phase="phase_3_synthesis",
            extra={"result": judge_synthesis.model_dump()},
        )

        # ──────────────────────────────────────────────────────────────────────
        # Round 5: Stance Voting & Final Consensus Metric
        # ──────────────────────────────────────────────────────────────────────
        await self.broadcaster.phase_announce(
            "🗳️ Round 5: Stance Voting — 6 Panelists casting final endorsement votes (AGREE / REVISE / DISSENT) on the Chief Magistrate's synthesis...",
            phase="phase_4_revision",
        )

        async def run_panelist_voting(panelist: PanelistAgent) -> PanelistVote:
            stream_cb = self.broadcaster.create_stream_callback(
                source=panelist.panelist_id,
                phase="phase_4_revision",
            )
            vote = await panelist.vote_stance(
                incident=incident,
                judge_synthesis=judge_synthesis,
                stream_callback=stream_cb,
            )
            await self.broadcaster.broadcast(
                event_type="panelist_vote",
                source=panelist.panelist_id,
                text=f"[{panelist.name}] Voted {vote.stance.value}: {vote.rationale}",
                phase="phase_4_revision",
                extra={"vote": vote.model_dump()},
            )
            await self.broadcaster.broadcast(
                event_type="debate_revision",
                source=panelist.panelist_id,
                text=f"[{panelist.name}] {vote.stance.value}: {vote.rationale}",
                phase="phase_4_revision",
                extra={"vote": vote.model_dump()},
            )
            return vote

        panel_votes: List[PanelistVote] = await asyncio.gather(*[run_panelist_voting(p) for p in panelists])

        agree_count = sum(1 for v in panel_votes if v.stance == DebateStance.AGREE)
        revise_count = sum(1 for v in panel_votes if v.stance == DebateStance.REVISE)
        dissent_count = sum(1 for v in panel_votes if v.stance == DebateStance.DISSENT)
        total_panelists = len(panel_votes) or 6

        raw_consensus = (agree_count * 1.0 + revise_count * 0.6 + dissent_count * 0.0) / total_panelists
        consensus_score = round(min(1.0, max(0.0, raw_consensus)), 3)
        consensus_pct = consensus_score * 100.0

        if consensus_pct >= 85.0:
            consensus_status = "FULL_CONSENSUS"
        elif consensus_pct >= 65.0:
            consensus_status = "STRONG_CONSENSUS"
        elif consensus_pct >= 45.0:
            consensus_status = "SPLIT_PANEL"
        else:
            consensus_status = "DISSENT"

        consensus_metric = ConsensusMetric(
            status=consensus_status,
            consensus_score=consensus_score,
            agree_count=agree_count,
            revise_count=revise_count,
            dissent_count=dissent_count,
            total_panelists=total_panelists,
            notes=f"{agree_count}/{total_panelists} panelists agreed, {revise_count} proposed revisions, {dissent_count} dissented.",
        )

        # Backward compatibility synthesis
        primary_delib = r1_deliberations[0] if r1_deliberations else None
        valid_evidence = primary_delib.grounded_evidence if (primary_delib and primary_delib.grounded_evidence) else [f"endpoint: {incident.raw_log_details.get('endpoint') or (incident.affected_endpoints[0] if incident.affected_endpoints else '/')}", f"category: {incident.category}"]
        raw_ep = incident.raw_log_details.get("endpoint") or (incident.affected_endpoints[0] if incident.affected_endpoints else "/")
        recon_ep = primary_delib.entry_point if (primary_delib and primary_delib.entry_point and primary_delib.entry_point != "/api/v1/resource") else raw_ep
        
        recon_result = ReconstructionResult(
            incident_id=incident.incident_id,
            entry_point=recon_ep,
            attack_sequence=primary_delib.attack_sequence if (primary_delib and primary_delib.attack_sequence) else judge_synthesis.technical_timeline,
            underlying_condition=primary_delib.root_cause_hypothesis if primary_delib else judge_synthesis.root_cause_analysis,
            grounded_evidence_fields=valid_evidence,
            raw_response=primary_delib.raw_response if primary_delib else "",
            model_provider=primary_delib.model_provider if primary_delib else "anthropic",
        )

        # Grounded timeline synthesis
        grounded_timeline = None
        try:
            grounded_timeline = TimelineCorrelator.build_grounded_timeline(
                incident=incident,
                reconstruction=recon_result,
                supplemental_logs=supplemental_logs,
            )
        except Exception as te:
            logger.debug("Deep-Lane timeline correlation error: %s", te)

        response_plan = ResponsePlan(
            incident_id=incident.incident_id,
            immediate_containment=[a.title for a in judge_synthesis.ranked_actions if a.category == "CONTAINMENT"] or ["Isolate attacker session", "Apply WAF filtering"],
            architectural_prevention=[a.title for a in judge_synthesis.ranked_actions if a.category == "ARCHITECTURAL_PREVENTION"] or ["Deploy AST boundary validation"],
            requires_human_approval=judge_synthesis.requires_human_approval,
            human_approval_reasoning=judge_synthesis.human_approval_justification,
            actions=judge_synthesis.ranked_actions,
            raw_response="",
            model_provider=judge_synthesis.model_provider,
        )

        legacy_revisions: List[RevisionFeedback] = [
            RevisionFeedback(
                agent_role=AgentRole.RECONSTRUCTION,
                model_provider=panel_votes[0].model_provider if panel_votes else "anthropic",
                stance=panel_votes[0].stance if panel_votes else DebateStance.AGREE,
                rationale=panel_votes[0].rationale if panel_votes else "Reconstruction verified.",
                revised_points=panel_votes[0].suggested_revisions if panel_votes else [],
                raw_response=panel_votes[0].rationale if panel_votes else "",
            ),
            RevisionFeedback(
                agent_role=AgentRole.RESPONSE,
                model_provider=panel_votes[3].model_provider if len(panel_votes) > 3 else (panel_votes[-1].model_provider if panel_votes else "openai"),
                stance=panel_votes[3].stance if len(panel_votes) > 3 else (panel_votes[-1].stance if panel_votes else DebateStance.AGREE),
                rationale=panel_votes[3].rationale if len(panel_votes) > 3 else (panel_votes[-1].rationale if panel_votes else "Response plan confirmed."),
                revised_points=panel_votes[3].suggested_revisions if len(panel_votes) > 3 else (panel_votes[-1].suggested_revisions if panel_votes else []),
                raw_response=panel_votes[3].rationale if len(panel_votes) > 3 else (panel_votes[-1].rationale if panel_votes else ""),
            ),
        ]

        report = FinalExplanationReport(
            report_id=f"REP-{incident.incident_id}-{uuid.uuid4().hex[:6]}",
            incident_id=incident.incident_id,
            org_id="org_default",
            generated_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            execution_lane="DEEP_LANE",
            executive_summary=judge_synthesis.executive_summary,
            incident_category=incident.category,
            detection_mesh_confidence=incident.confidence,
            consensus_metric=consensus_metric,
            panel_consensus_score=consensus_pct,
            requires_human_approval=judge_synthesis.requires_human_approval,
            human_approval_reasoning=judge_synthesis.human_approval_justification,
            root_cause=judge_synthesis.root_cause_analysis,
            technical_timeline=judge_synthesis.technical_timeline,
            reconstruction_findings=recon_result,
            response_plan=response_plan,
            judge_synthesis=judge_synthesis,
            debate_revisions=legacy_revisions,
            ranked_actions=judge_synthesis.ranked_actions,
            round1_reconstructions=r1_deliberations,
            round2_responses=r2_deliberations,
            cross_examinations=all_cross_examinations,
            panel_deliberations=all_deliberations,
            peer_critiques=all_peer_critiques,
            panel_votes=panel_votes,
            participating_models=participating_models,
            risk_assessment=risk_assessment,
            grounded_timeline=grounded_timeline,
        )

        # Record transcript to distillation pipeline
        try:
            transcript = DebateTranscript(
                session_id=session_id,
                incident_id=incident.incident_id,
                category=incident.category,
                incident_record=incident,
                reconstruction_result=recon_result,
                response_plan=response_plan,
                judge_synthesis=judge_synthesis,
                debate_revisions=legacy_revisions,
                consensus_metric=consensus_metric,
                final_report=report,
                quality_score=0.95 if consensus_score >= 0.85 else 0.70,
                is_distillation_exemplar=consensus_score >= 0.85,
            )
            self.distillation_pipeline.record_transcript(transcript)
        except Exception as dist_exc:
            logger.debug("Distillation pipeline notice: %s", dist_exc)

        await self.broadcaster.phase_announce(
            f"✅ Browser Council v2 complete — Consensus Score: {consensus_pct:.1f}% ({consensus_status}) across 7 models.",
            phase="phase_5_consensus",
        )
        await self.broadcaster.broadcast(
            event_type="debate_complete",
            source="council_engine",
            text=f"7-Model Council Debate finalized. Incident {incident.incident_id} explained with {consensus_status} ({consensus_pct:.1f}%).",
            phase="phase_5_consensus",
            extra={"report": report.model_dump()},
        )
        await self.broadcaster.broadcast(
            event_type="council_complete",
            source="council_engine",
            text=f"Council complete for {incident.incident_id}.",
            phase="phase_5_consensus",
            extra={"report": report.model_dump()},
        )
        return report
