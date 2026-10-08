"""
MADDY Conversational Assistant Engine for MAD-PS Ecosystem.
Executes intent-guided retrieval grounding, multi-tenant memory retention,
token-by-token streaming over WebSockets, inline incident card generation,
proactive incident alerting (Task L5), and in-chat action authorization (Task L5).
"""

from __future__ import annotations

import asyncio
import datetime
import inspect
import json
import logging
import re
import uuid
from typing import Any, Callable, Dict, List, Optional, Set
from fastapi import WebSocket

from database import SharedProductDatabase, shared_db
from decisions.decision_manager import DecisionManager
from grounding.models import GroundingCitation, GroundingContext, GroundingSourceType
from grounding.retriever import GroundingRetriever, grounding_retriever
from llm.base import BaseLLMProvider
from llm.config_manager import llm_config_manager
from llm.factory import LLMFactory
from schemas.decision import DecisionType

from .intent import IntentClassifier
from .models import (
    ActionCommand,
    AssistantIntentType,
    AssistantQuery,
    AssistantResponse,
    AssistantStreamEvent,
    DecisionSubmission,
    InlineIncidentCard,
    PendingActionItem,
    ProactiveAlertPayload,
)

logger = logging.getLogger("mad_ps_explanation.assistant")


SYSTEM_PROMPT_TEMPLATE = """You are MADDY (Multi-Agent Dialogue & Defense Yield), the autonomous cybersecurity conversational copilot and SOC analyst colleague for the MAD-PS platform.

CORE PERSONA & CONVERSATIONAL STYLE:
1. KNOWLEDGEABLE, DIRECT, SLIGHTLY INFORMAL: Communicate like a sharp, seasoned SOC analyst colleague in Slack/Teams—direct, clear, technically rigorous, and collaborative. Avoid robotic corporate boilerplate, generic AI preambles, and exaggerated sci-fi caricatures.
2. CONVERSATIONAL VARIETY: Never open every response with the same formulaic phrase (e.g., avoid repeating "I've detected..." or "Greetings SOC analyst" every time). Vary your syntax, tone, and opening cadence naturally across turns.
3. HONEST UNCERTAINTY & CALIBRATION: Be confident when verified telemetry supports your findings; be completely candid when data is missing, ambiguous, or borderline. If the Council had split opinions or model branch confidence was low, state the divergence directly rather than projecting false certainty.
4. GROUNDED FIDELITY: Rely strictly on the verified facts in the Grounding Context. Never fabricate unobserved metrics, timestamps, or raw payloads. Mention full incident identifiers (e.g. INC-20260904-AFEBE9) when referencing incidents.

5-POINT DEEP ML DETECTION NARRATION STRUCTURE:
When explaining a detected incident, security event, or exploit attempt, cover these 5 core points with natural, engaging phrasing grounded in the real retrieved telemetry:
1. WHAT HAPPENED: Plain-language, grounded description of the actual request (HTTP method, endpoint path, parameter/payload data, and timestamp).
2. HOW IT HAPPENED: The underlying technical vulnerability mechanism and CWE/exploit pattern (e.g., backend trusted client-supplied price or IDOR parameter without server-side validation).
3. HOW THE SYSTEM CAUGHT IT: Granular 8-model detection mesh breakdown. Pull specific branch scores (e.g., SVM, DNN, LSTM, Isolation Forest, XGBoost) and explain the analytical differences (e.g., whether the LSTM caught a multi-step sequence pattern vs Isolation Forest flagging payload entropy, and how the meta-classifier combined them).
4. WHAT THE COUNCIL CONCLUDED: Pull the real panel consensus score (e.g., 94.2%) and summarize where the 7 panelists agreed or diverged (Forensics, Threat Intel, Exploit Code, Mitigation, Resilience, Compliance, Chief Judge).
5. WHAT SHOULD HAPPEN NEXT: Specific recommended remediation actions (P0 immediate containment vs P1 architectural prevention), risk score, and whether human approval is required.
"""


class MaddyAssistantEngine:
    """Core conversational agent for interactive SOC assistant dialogues."""

    def __init__(
        self,
        retriever: Optional[GroundingRetriever] = None,
        db: Optional[SharedProductDatabase] = None,
        llm_provider: Optional[BaseLLMProvider] = None,
        decision_manager: Optional[DecisionManager] = None,
    ) -> None:
        self.db = db or shared_db
        self.retriever = retriever or grounding_retriever
        self._custom_llm_provider = llm_provider
        self.decision_manager = decision_manager or DecisionManager()
        self._active_ws_subscribers: Set[WebSocket] = set()

    @property
    def active_llm_provider(self) -> BaseLLMProvider:
        """Return dynamically configured real or simulated LLM provider."""
        if self._custom_llm_provider is not None:
            return self._custom_llm_provider
        return llm_config_manager.get_assistant_provider()

    @property
    def llm_provider(self) -> BaseLLMProvider:
        return self.active_llm_provider

    def register_ws(self, websocket: WebSocket) -> None:
        """Register active WebSocket client for live assistant streaming and proactive alerts."""
        self._active_ws_subscribers.add(websocket)

    def unregister_ws(self, websocket: WebSocket) -> None:
        """Unregister WebSocket client."""
        self._active_ws_subscribers.discard(websocket)

    async def process_query_stream(
        self,
        query: AssistantQuery,
        event_callback: Optional[Callable[[AssistantStreamEvent], Any]] = None,
    ) -> AssistantResponse:
        """
        Stream conversational response token-by-token over WebSocket while persisting multi-tenant memory.
        Handles dynamic tool routing, conversational clarification, pronoun resolution, and deep ML narration.
        """
        # 1. Ensure conversation session exists
        conv_id = query.conversation_id
        if not conv_id:
            conv_id = self.db.create_conversation(
                user_id=query.user_id,
                org_id=query.org_id,
                title=query.query[:45],
            )

        # 2. Classify intent (supports multi-intent routing)
        intents = IntentClassifier.classify(query.query)

        # Emit intent event
        await self._emit(
            event_callback,
            AssistantStreamEvent(
                type="intent_classified",
                conversation_id=conv_id,
                intents=intents,
            ),
        )

        # 3. Retrieve real data grounding across Task L2 engines & resolve conversation memory (Task L3)
        grounding_ctx = self.retriever.retrieve(
            query=query.query,
            conversation_id=conv_id,
            org_id=query.org_id,
        )

        # Emit retrieval complete event
        await self._emit(
            event_callback,
            AssistantStreamEvent(
                type="retrieval_complete",
                conversation_id=conv_id,
                sources_cited=grounding_ctx.sources_queried,
            ),
        )

        # 4. Check for ambiguous questions requiring conversational clarification (Task AA2 #2)
        # If the user asks "what happened?" / "tell me about the attack" without specifying an ID,
        # and there is NO recent incident in conversation memory, ask ONE clarifying question.
        if self._is_ambiguous_incident_query(query.query, grounding_ctx):
            clarification_text = "Which incident are you asking about — the most recent one, or a specific incident ID?"
            await self._emit(
                event_callback,
                AssistantStreamEvent(
                    type="token",
                    conversation_id=conv_id,
                    token=clarification_text,
                ),
            )
            full_answer = clarification_text
            provider = self.active_llm_provider
        else:
            # 5. Construct grounded prompt with deep ML narration instructions
            prompt = self._build_grounded_prompt(query.query, grounding_ctx)

            # 6. Stream LLM tokens
            full_text_chunks: List[str] = []

            async def stream_handler(token_chunk: str):
                full_text_chunks.append(token_chunk)
                await self._emit(
                    event_callback,
                    AssistantStreamEvent(
                        type="token",
                        conversation_id=conv_id,
                        token=token_chunk,
                    ),
                )

            provider = self.active_llm_provider
            try:
                generated_text = await provider.generate(
                    prompt=prompt,
                    system_prompt=SYSTEM_PROMPT_TEMPLATE,
                    temperature=0.2,
                    max_tokens=2048,
                    stream_callback=stream_handler,
                )
                full_answer = generated_text or "".join(full_text_chunks)
            except Exception as exc:
                err_msg = str(exc)
                logger.error("LLM reasoning engine error: %s", exc)
                # Task AA1 #5: Visibly report real failure rather than silently faking an answer
                full_answer = (
                    f"⚠️ **Reasoning Engine Alert**: I'm having trouble reaching my reasoning engine right now: {err_msg}. "
                    f"Please verify your `GEMINI_API_KEY` configuration in `.env` or AI Settings."
                )
                await self._emit(
                    event_callback,
                    AssistantStreamEvent(
                        type="token",
                        conversation_id=conv_id,
                        token=full_answer,
                    ),
                )

        # 7. Extract referenced incidents, pending actions, and action commands
        inline_cards = self._extract_inline_incident_cards(query.query, full_answer, grounding_ctx, query.org_id)
        pending_actions = self._extract_pending_actions(grounding_ctx)
        action_cmd = self._extract_action_command(query.query, full_answer, grounding_ctx)

        # 8. Persist turn to multi-tenant conversation memory (Task L3)
        user_msg_id = self.db.append_message(
            conversation_id=conv_id,
            user_id=query.user_id,
            org_id=query.org_id,
            role="user",
            content=query.query,
        )

        assistant_msg_id = self.db.append_message(
            conversation_id=conv_id,
            user_id=query.user_id,
            org_id=query.org_id,
            role="assistant",
            content=full_answer,
            sources_cited=[s.source_identifier for s in grounding_ctx.sources_queried],
            retrieved_context=grounding_ctx.to_prompt_context(),
        )

        # 9. Emit final done event with sources, action authorization, and UI action triggers
        await self._emit(
            event_callback,
            AssistantStreamEvent(
                type="done",
                conversation_id=conv_id,
                message_id=assistant_msg_id,
                sources_cited=grounding_ctx.sources_queried,
                inline_incidents=inline_cards,
                pending_actions=pending_actions,
                action_command=action_cmd,
                provider_used=getattr(provider, "provider_name", "llm"),
                model_used=getattr(provider, "model_name", "unknown"),
                full_text=full_answer,
            ),
        )

        return AssistantResponse(
            conversation_id=conv_id,
            message_id=assistant_msg_id,
            query=query.query,
            answer=full_answer,
            intents=intents,
            is_grounded=grounding_ctx.is_grounded,
            sources_cited=grounding_ctx.sources_queried,
            inline_incidents=inline_cards,
            pending_actions=pending_actions,
            action_command=action_cmd,
            provider_used=getattr(provider, "provider_name", "llm"),
            model_used=getattr(provider, "model_name", "unknown"),
        )

    def _is_ambiguous_incident_query(self, query: str, ctx: GroundingContext) -> bool:
        """
        Check if a query is an ambiguous question about an incident where no ID was provided
        and no incident context exists in the conversation history (Task AA2 #2).
        """
        q_lower = query.lower().strip()
        # Vague inquiry patterns
        vague_patterns = [
            r"^what happened\??$",
            r"^what was that\??$",
            r"^tell me what happened\??$",
            r"^why did that happen\??$",
            r"^what was that attack\??$",
            r"^tell me about the breach\??$",
            r"^why was it flagged\??$",
            r"^what attack\??$",
            r"^explain the incident\??$",
        ]
        is_vague = any(re.match(p, q_lower) for p in vague_patterns) or (
            q_lower in ["what happened", "what happened?", "what was that", "why did this happen", "explain attack"]
        )

        if not is_vague:
            return False

        # If an explicit incident ID is in the query (e.g. INC-..., #1042), not ambiguous
        if re.search(r"\b(INC-[\w-]+)\b", query, re.IGNORECASE) or re.search(r"#\w+", query):
            return False

        # If a specific URL or attack category is in query, not ambiguous
        if any(cat in q_lower for cat in ["sql", "xss", "ssrf", "bola", "idor", "auth", "brute", "pricing", "deserialization"]):
            return False

        # If conversation history already has an active incident ID referenced, resolve from context
        if ctx.conversation_history:
            for turn in reversed(ctx.conversation_history):
                r_ctx = turn.get("retrieved_context", {})
                if isinstance(r_ctx, dict) and r_ctx.get("incident_id"):
                    return False

        return True

    # ──────────────────────────────────────────────────────────────────────────
    # Task L5: Proactive Event-Driven Alerting ("JARVIS" Behavior)
    # ──────────────────────────────────────────────────────────────────────────
    async def broadcast_proactive_alert(
        self,
        report_dict: Dict[str, Any],
        org_id: str = "org_default",
    ) -> ProactiveAlertPayload:
        """
        Proactively notify active SOC operators when a HIGH or CRITICAL incident lands,
        including in-chat action authorization cards for human sign-off.
        """
        inc_id = report_dict.get("incident_id", "INC-UNKNOWN")
        rep_id = report_dict.get("report_id", f"REP-{inc_id}")
        cat = report_dict.get("incident_category", "THREAT")
        risk = report_dict.get("risk_assessment", {})
        risk_score = float(report_dict.get("risk_score") if report_dict.get("risk_score") is not None else (risk.get("score") if isinstance(risk, dict) else 8.5))
        sev = str(report_dict.get("risk_severity_band") or (risk.get("severity_band") if isinstance(risk, dict) else "HIGH"))
        req_approval = bool(report_dict.get("requires_human_approval"))

        # Extract target endpoint and origin if present
        recon = report_dict.get("reconstruction_findings", {})
        entry_point = recon.get("entry_point") if isinstance(recon, dict) else "/api/v1/resource"

        # Construct conversational proactivity message
        if req_approval:
            approval_reason = report_dict.get("human_approval_reasoning") or "P1 architectural code or configuration modifications require human sign-off."
            message = (
                f"🚨 **Heads up** — The Detection Mesh just caught an active **{cat}** exploit on `{entry_point}` with a Risk Score of **{risk_score:.1f}/10.0 ({sev})**. "
                f"The Council has synthesized immediate autonomous containment, but has flagged **P1 Architectural Prevention** for human authorization: *\"{approval_reason}\"*. "
                f"Please review and authorize the pending action below."
            )
        else:
            message = (
                f"⚠️ **Notice** — Detection Mesh identified a **{cat}** attempt on `{entry_point}` (Risk: **{risk_score:.1f}/10.0 {sev}**). "
                f"The Council executed autonomous P0 containment. Full telemetry report logged below."
            )

        # Construct pending actions
        pending_actions: List[PendingActionItem] = []
        raw_actions = report_dict.get("ranked_actions", [])
        for a in raw_actions:
            if isinstance(a, dict) and a.get("requires_human_approval"):
                pending_actions.append(
                    PendingActionItem(
                        action_id=a.get("action_id", "ACT-01"),
                        priority=a.get("priority", "P1_HIGH"),
                        category=a.get("category", "ARCHITECTURAL_PREVENTION"),
                        title=a.get("title", f"Deploy {cat} Guard"),
                        description=a.get("description", "Apply declarative authorization check."),
                        target_component=a.get("target_component", "Backend Application"),
                        estimated_impact=a.get("estimated_impact"),
                        requires_human_approval=True,
                        approval_reasoning=a.get("approval_reasoning") or report_dict.get("human_approval_reasoning"),
                    )
                )

        inline_cards = [
            InlineIncidentCard(
                incident_id=inc_id,
                category=cat,
                severity=sev,
                risk_score=risk_score,
                executive_summary=report_dict.get("executive_summary", "")[:120] + "...",
            )
        ]

        alert_payload = ProactiveAlertPayload(
            incident_id=inc_id,
            report_id=rep_id,
            category=cat,
            severity=sev,
            risk_score=risk_score,
            message=message,
            inline_incidents=inline_cards,
            pending_actions=pending_actions,
            requires_human_approval=req_approval,
        )

        # 1. Record into organization's active conversation memory
        convs = self.db.list_user_conversations(user_id="soc_analyst_1", org_id=org_id, limit=1)
        conv_id = convs[0]["conversation_id"] if convs else self.db.create_conversation(user_id="soc_analyst_1", org_id=org_id, title="Proactive Incident Stream")

        self.db.append_message(
            conversation_id=conv_id,
            user_id="soc_analyst_1",
            org_id=org_id,
            role="assistant",
            content=message,
            sources_cited=[f"incident_reports:{inc_id}"],
            retrieved_context={"incident_id": inc_id, "category": cat, "risk_score": risk_score, "proactive": True},
        )

        # 2. Broadcast to all active WebSocket clients
        event = AssistantStreamEvent(
            type="proactive_notification",
            conversation_id=conv_id,
            sources_cited=[
                GroundingCitation(
                    source_type=GroundingSourceType.INCIDENT_RECORD,
                    source_identifier=f"incident_reports:{inc_id}",
                    summary=f"Proactive Council alert for {inc_id} ({cat})",
                    raw_evidence=report_dict,
                )
            ],
            inline_incidents=inline_cards,
            pending_actions=pending_actions,
            proactive_payload=alert_payload,
            full_text=message,
        )

        dead_sockets = set()
        for ws in self._active_ws_subscribers:
            try:
                await ws.send_text(event.model_dump_json())
            except Exception as exc:
                logger.debug("Failed sending proactive alert to client: %s", exc)
                dead_sockets.add(ws)

        for ws in dead_sockets:
            self._active_ws_subscribers.discard(ws)

        logger.info("MADDY broadcast proactive alert for incident %s (Risk: %.2f) to %d clients", inc_id, risk_score, len(self._active_ws_subscribers))
        return alert_payload

    # ──────────────────────────────────────────────────────────────────────────
    # Task L5: In-Chat Action Authorization Handler
    # ──────────────────────────────────────────────────────────────────────────
    def handle_action_decision(self, submission: DecisionSubmission) -> Dict[str, Any]:
        """Process analyst Approve/Reject action decisions submitted in chat."""
        try:
            d_type = DecisionType(submission.decision.upper())
        except ValueError:
            d_type = DecisionType.APPROVED if "APPROV" in submission.decision.upper() else DecisionType.REJECTED

        decision_record = self.decision_manager.record_decision(
            incident_id=submission.incident_id,
            report_id=submission.report_id,
            action_id=submission.action_id,
            decision=d_type,
            action_title=f"Action {submission.action_id} for {submission.incident_id}",
            target_component="SOC Orchestrator",
            priority="P1_HIGH",
            analyst_id=submission.analyst_id,
            comments=submission.comments,
            modification_details=submission.modification_details,
        )

        convs = self.db.list_user_conversations(user_id=submission.analyst_id, org_id=submission.org_id, limit=1)
        if convs:
            status_text = "APPROVED" if d_type == DecisionType.APPROVED else "REJECTED"
            self.db.append_message(
                conversation_id=convs[0]["conversation_id"],
                user_id=submission.analyst_id,
                org_id=submission.org_id,
                role="assistant",
                content=f"Action **{submission.action_id}** for incident **{submission.incident_id}** has been **{status_text}** by analyst `{submission.analyst_id}` (Decision ID: `{decision_record.decision_id}`). Execution readiness recorded in audit log.",
                sources_cited=[f"decisions:{decision_record.decision_id}"],
                retrieved_context={"decision_id": decision_record.decision_id, "action_id": submission.action_id, "decision": status_text},
            )

        return decision_record.model_dump()

    # ──────────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────────
    def _build_grounded_prompt(self, query: str, ctx: GroundingContext) -> str:
        """Combine conversation history and real retrieved data into a strict RAG prompt."""
        parts = []

        # Grounding Context Section
        parts.append("=== GROUNDING CONTEXT (FACTUAL DATA RETRIEVED FROM REAL PLATFORM) ===")
        parts.append(ctx.to_grounding_prompt_block())

        if ctx.incident_data:
            parts.append(f"\n[INCIDENT EXPLANATION RECORD]:\n{json.dumps(ctx.incident_data, indent=2)}")

        if ctx.council_transcript:
            parts.append(f"\n[7-PANELIST COUNCIL TRANSCRIPT & DELIBERATIONS]:\n{json.dumps(ctx.council_transcript, indent=2)}")

        if ctx.branch_scores:
            parts.append(f"\n[8-MODEL DETECTION MESH BRANCH SCORES]:\n{json.dumps(ctx.branch_scores, indent=2)}")

        if ctx.raw_log:
            parts.append(f"\n[VERBATIM RAW TELEMETRY / HTTP REQUEST LOG]:\n{json.dumps(ctx.raw_log, indent=2)}")

        if ctx.mesh_health:
            parts.append(f"\n[LIVE DETECTION MESH HEALTH & STATUS]:\n{json.dumps(ctx.mesh_health, indent=2)}")

        if ctx.aggregate_stats:
            parts.append(f"\n[SQL AGGREGATE PLATFORM METRICS]:\n{json.dumps(ctx.aggregate_stats, indent=2)}")

        if ctx.benchmark_metrics:
            parts.append(f"\n[MODEL PERFORMANCE BENCHMARKS (PHASE F GROUND TRUTH)]:\n{json.dumps(ctx.benchmark_metrics, indent=2)}")

        if ctx.architecture_doc:
            parts.append(f"\n[DOCUMENTED PLATFORM ARCHITECTURE]:\n{json.dumps(ctx.architecture_doc, indent=2)}")

        if ctx.unretrieved_reason:
            parts.append(f"\n[UNRETRIEVED NOTICE]: {ctx.unretrieved_reason}")

        # Dialogue History Section
        if ctx.conversation_history:
            parts.append("\n=== RECENT CONVERSATION HISTORY ===")
            for turn in ctx.conversation_history[-6:]:
                role = turn.get("role", "user").upper()
                content = turn.get("content", "")
                parts.append(f"{role}: {content}")

        # Current User Question & Instruction
        parts.append(f"\n=== CURRENT ANALYST QUERY ===\n{query}")
        if ctx.incident_data:
            parts.append(
                "\nINCIDENT BRIEFING INSTRUCTION:\n"
                "Structure your explanation directly into 5 clear sections:\n"
                "1. **What Happened**: Plain-language description of the request payload, method, endpoint, and timestamp.\n"
                "2. **How It Happened**: The underlying vulnerability mechanism and exploit pattern.\n"
                "3. **How the 8-Model Detection Mesh Caught It**: Explicit breakdown of the 8 ML branch scores (SVM, DNN, XGBoost, LSTM, Isolation Forest, etc.) and why they scored it as they did.\n"
                "4. **What the Council Concluded**: The panel consensus score, panelist deliberations, and Chief Magistrate verdict.\n"
                "5. **What Should Happen Next**: Specific remediation actions (P0 immediate containment vs P1 architectural prevention), risk score, and human approval status."
            )
        else:
            parts.append(
                "\nSynthesize your response for the analyst based strictly on the factual Grounding Context above."
            )

        return "\n".join(parts)

    def _extract_inline_incident_cards(
        self,
        query: str,
        answer: str,
        ctx: GroundingContext,
        org_id: str,
    ) -> List[InlineIncidentCard]:
        """Detect referenced incidents in text and pull summary metadata for clickable UI cards."""
        combined = f"{query} {answer}"
        matches = set(re.findall(r"\b(INC-[\w-]+)\b", combined, re.IGNORECASE))
        for m in re.findall(r"#(\w+)", combined):
            matches.add(f"INC-{m.upper()}")

        cards: List[InlineIncidentCard] = []
        for inc_id in matches:
            inc_id_norm = inc_id.upper()
            rep = None
            if ctx.incident_data and ctx.incident_data.get("incident_id", "").upper() == inc_id_norm:
                rep = ctx.incident_data
            else:
                rep = self.db.get_incident_report(inc_id_norm, org_id=org_id)

            if rep:
                risk = rep.get("risk_assessment", {})
                risk_score = (
                    rep.get("risk_score")
                    if rep.get("risk_score") is not None
                    else (risk.get("score") if isinstance(risk, dict) else None)
                )
                severity = (
                    rep.get("risk_severity_band")
                    or (risk.get("severity_band") if isinstance(risk, dict) else None)
                    or "MEDIUM"
                )
                cards.append(
                    InlineIncidentCard(
                        incident_id=rep.get("incident_id", inc_id_norm),
                        category=rep.get("incident_category", "UNKNOWN"),
                        severity=severity,
                        risk_score=float(risk_score) if risk_score is not None else 7.5,
                        executive_summary=rep.get("executive_summary", "")[:120] + "...",
                    )
                )

        return cards

    def _extract_pending_actions(self, ctx: GroundingContext) -> List[PendingActionItem]:
        """Extract actions requiring approval from grounded incident data if applicable."""
        actions: List[PendingActionItem] = []
        if ctx.incident_data:
            for a in ctx.incident_data.get("ranked_actions", []):
                if isinstance(a, dict) and a.get("requires_human_approval"):
                    actions.append(
                        PendingActionItem(
                            action_id=a.get("action_id", "ACT-01"),
                            priority=a.get("priority", "P1_HIGH"),
                            category=a.get("category", "ARCHITECTURAL_PREVENTION"),
                            title=a.get("title", "Remediation Action"),
                            description=a.get("description", "Implement architectural fix."),
                            target_component=a.get("target_component", "Backend Application"),
                            estimated_impact=a.get("estimated_impact"),
                            requires_human_approval=True,
                            approval_reasoning=a.get("approval_reasoning"),
                        )
                    )
        return actions

    def _extract_action_command(
        self,
        query: str,
        answer: str,
        ctx: GroundingContext,
    ) -> Optional[ActionCommand]:
        """Detect natural language voice/text intent commands and emit actionable UI directives."""
        q_lower = query.lower().strip()

        # 1. URL Inspection Command (e.g., "Inspect URL https://...")
        url_match = re.search(r"(?:inspect|scan|check|test)\s+(?:url|website|site|endpoint)?\s*(https?://[^\s]+)", query, re.IGNORECASE)
        if url_match:
            target_url = url_match.group(1).rstrip(",.;)")
            return ActionCommand(
                action="EXECUTE_INSPECTION",
                target=target_url,
                parameters={"url": target_url, "method": "GET"},
            )

        # 2. Payload Inspection Command (e.g., "Inspect payload ' OR 1=1--")
        payload_match = re.search(r"(?:inspect|scan|test)\s+payload\s+([^\n]+)", query, re.IGNORECASE)
        if payload_match:
            raw_payload = payload_match.group(1).strip()
            return ActionCommand(
                action="EXECUTE_INSPECTION",
                target="payload",
                payload={"payload": raw_payload, "category": "CUSTOM_PROBE"},
            )

        # 3. Convene Council Command (e.g., "Convene council for incident INC-...")
        if any(k in q_lower for k in ["convene council", "convene the council", "start debate", "debate incident", "convene 3-agent"]):
            inc_id = self._extract_incident_id_from_text(f"{query} {answer}") or (ctx.incident_data.get("incident_id") if ctx.incident_data else None)
            return ActionCommand(
                action="CONVENE_COUNCIL",
                target=inc_id or "LATEST",
            )

        # 4. Tab Navigation Commands
        if any(k in q_lower for k in ["show dbms", "open dbms", "show database", "open explorer", "view database", "database explorer"]):
            return ActionCommand(action="NAVIGATE_TAB", target="dbms")
        if any(k in q_lower for k in ["show topology", "show mesh", "view mesh", "mesh topology", "branch health"]):
            return ActionCommand(action="NAVIGATE_TAB", target="topology")
        if any(k in q_lower for k in ["show inspector", "open inspector", "live inspector", "website inspector"]):
            return ActionCommand(action="NAVIGATE_TAB", target="inspector")
        if any(k in q_lower for k in ["show council", "council chamber", "view debate"]):
            return ActionCommand(action="NAVIGATE_TAB", target="council")
        if any(k in q_lower for k in ["show soc", "operations center", "sentinel center", "dashboard", "live feed"]):
            return ActionCommand(action="NAVIGATE_TAB", target="soc")

        # 5. Action Authorization Commands (e.g., "Authorize action ACT-01")
        if any(k in q_lower for k in ["authorize action", "approve action", "approve remediation"]):
            act_match = re.search(r"\b(ACT-[\w-]+)\b", query, re.IGNORECASE)
            act_id = act_match.group(1).upper() if act_match else "ACT-01"
            return ActionCommand(action="AUTHORIZE_ACTION", target=act_id, parameters={"decision": "APPROVE"})

        if any(k in q_lower for k in ["reject action", "cancel action", "disapprove"]):
            act_match = re.search(r"\b(ACT-[\w-]+)\b", query, re.IGNORECASE)
            act_id = act_match.group(1).upper() if act_match else "ACT-01"
            return ActionCommand(action="AUTHORIZE_ACTION", target=act_id, parameters={"decision": "REJECT"})

        return None

    @staticmethod
    def _extract_incident_id_from_text(text: str) -> Optional[str]:
        m = re.search(r"\b(INC-[\w-]+)\b", text, re.IGNORECASE)
        return m.group(1).upper() if m else None

    @staticmethod
    async def _emit(callback: Optional[Callable[[AssistantStreamEvent], Any]], event: AssistantStreamEvent) -> None:
        if not callback:
            return
        if inspect.iscoroutinefunction(callback):
            await callback(event)
        else:
            callback(event)


# Global MADDY Assistant Engine
maddy_assistant = MaddyAssistantEngine()
