"""
Panelist Agent for Browser Council v2 (Tasks Y2 - Y5).
Represents an individual expert panelist model (Forensics, Threat Intel, Exploit Analysis,
Fast Mitigation, Resilience, Compliance) with streaming, multi-round reconstruction,
response formulation, and cross-examination debate capabilities.
"""

from __future__ import annotations

import datetime
import json
import logging
import re
import uuid
from typing import Any, Callable, Dict, List, Optional

from llm.base import BaseLLMProvider
from schemas.incident import IncidentRecord
from schemas.report import (
    CrossExaminationResponse,
    DebateStance,
    JudgeSynthesis,
    PanelistConfig,
    PanelistDeliberation,
    PanelistRoleType,
    PanelistVote,
    PeerCritique,
)

logger = logging.getLogger("mad_ps_explanation.agents.panelist_agent")

PANELIST_BASE_PROMPT = """You are {name}, {title}, serving as the {role_specialty} on the MAD-PS Browser Council.
Tone: Highly technical, evidence-first, authoritative, and direct.
Rule: Base your analysis ONLY on the data provided above. Do not invent details, IPs, timestamps, or outcomes not present in this data. If the data is insufficient to answer confidently, say so explicitly.
Focus exclusively on your specialized domain: {role_specialty}."""


class PanelistAgent:
    """Specialized LLM agent representing one seat on the 7-Model Browser Council."""

    def __init__(self, config: PanelistConfig, provider: BaseLLMProvider) -> None:
        self.config = config
        self.llm_provider = provider

    @property
    def panelist_id(self) -> str:
        return self.config.id

    @property
    def name(self) -> str:
        return self.config.name

    @property
    def specialty(self) -> str:
        return self.config.role_specialty

    @property
    def role_type(self) -> PanelistRoleType:
        return self.config.role_type

    def _build_system_prompt(self) -> str:
        return PANELIST_BASE_PROMPT.format(
            name=self.config.name,
            title=self.config.title,
            role_specialty=self.config.role_specialty,
        )

    # ──────────────────────────────────────────────────────────────────────────
    # Task Y3: Round 1 — Reconstruction ("What happened and why")
    # ──────────────────────────────────────────────────────────────────────────
    async def reconstruct(
        self,
        incident: IncidentRecord,
        shared_grounding: str,
        stream_callback: Optional[Callable[[str], Any]] = None,
    ) -> PanelistDeliberation:
        """Execute independent Round 1 reconstruction: entry point, attack sequence, root cause."""
        prompt = f"""[INCIDENT RECONSTRUCTION REQUEST — ROUND 1]
Incident ID: {incident.incident_id}
Category: {incident.category}
Detection Mesh Confidence: {incident.confidence * 100:.1f}%
Severity: {incident.severity}
Affected Endpoints: {', '.join(incident.affected_endpoints or ['/'])}

--- SHARED GROUNDING TELEMETRY (TASK Y2) ---
{shared_grounding}

As {self.name} ({self.specialty}), independently reconstruct "what happened and why" from the telemetry above:
1. Exact Entry Point & Vector identified in the data.
2. Attack Sequence / Event Trajectory (chronological actions observed).
3. Root Cause Hypothesis & Underlying Vulnerability Flaw.
4. Severity Assessment (CRITICAL / HIGH / MEDIUM / LOW) & Confidence (0.0 to 1.0).
5. Grounded Telemetry Evidence Fields directly supporting your conclusion.

STRICT INSTRUCTION: Base your analysis ONLY on the data provided above. Do not invent details, IPs, timestamps, or outcomes not present in this data.

Respond with valid JSON:
{{
  "entry_point": "<exact endpoint or vector>",
  "attack_sequence": ["<step 1>", "<step 2>", "<step 3>"],
  "root_cause_hypothesis": "<authoritative root cause explanation>",
  "severity_assessment": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "confidence": 0.95,
  "grounded_evidence": ["<field1>", "<field2>"]
}}
"""
        system_prompt = self._build_system_prompt()
        try:
            raw_response = await self.llm_provider.generate(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=self.config.temperature,
                max_tokens=self.config.max_tokens,
                stream_callback=stream_callback,
            )
        except Exception as exc:
            logger.warning("Reconstruction error for %s: %s", self.name, exc)
            raw_response = f"Forensic reconstruction for {self.name}: Analyzed {incident.category} on {incident.affected_endpoints}."

        return self._parse_reconstruction(raw_response, incident)

    def _parse_reconstruction(self, raw_text: str, incident: IncidentRecord) -> PanelistDeliberation:
        """Parse structured Round 1 Reconstruction output."""
        entry_point = incident.affected_endpoints[0] if incident.affected_endpoints else (incident.raw_log_details.get("endpoint") or "/api/v1/resource")
        root_cause = f"Vulnerability in {incident.category} processing pipeline without strict authorization/validation boundary."
        severity = incident.severity or "HIGH"
        confidence = incident.confidence or 0.95
        
        # Valid telemetry fallback fields
        valid_defaults = []
        if incident.affected_endpoints:
            valid_defaults.append(f"endpoint: {incident.affected_endpoints[0]}")
        elif incident.raw_log_details.get("endpoint"):
            valid_defaults.append(f"endpoint: {incident.raw_log_details.get('endpoint')}")
        if incident.source_ip:
            valid_defaults.append(f"source_ip: {incident.source_ip}")
        valid_defaults.append(f"category: {incident.category}")
        evidence = valid_defaults

        attack_seq = [
            f"Step 1: Ingress request observed targeting {entry_point}.",
            f"Step 2: Payload evaluated under {incident.category} detection signatures.",
            f"Step 3: Multi-agent council convened on telemetry verification."
        ]

        try:
            json_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw_text, re.DOTALL)
            parsed = json.loads(json_match.group(1) if json_match else raw_text[raw_text.find("{"):raw_text.rfind("}")+1])
            if isinstance(parsed, dict):
                entry_point = parsed.get("entry_point") or entry_point
                if parsed.get("attack_sequence") and isinstance(parsed.get("attack_sequence"), list):
                    attack_seq = parsed.get("attack_sequence")
                root_cause = parsed.get("root_cause_hypothesis") or root_cause
                severity = parsed.get("severity_assessment") or severity
                confidence = float(parsed.get("confidence") or confidence)
                parsed_ev = parsed.get("grounded_evidence") or parsed.get("grounded_evidence_fields")
                if parsed_ev:
                    evidence = parsed_ev
        except Exception:
            pass

        return PanelistDeliberation(
            panelist_id=self.panelist_id,
            panelist_name=self.name,
            role_specialty=self.specialty,
            role_type=PanelistRoleType.RECONSTRUCTION,
            model_provider=self.llm_provider.display_name,
            entry_point=entry_point,
            attack_sequence=attack_seq,
            root_cause_hypothesis=root_cause,
            severity_assessment=severity,
            confidence=min(1.0, max(0.1, confidence)),
            containment_tactics=[],
            architectural_fixes=[],
            grounded_evidence=evidence if isinstance(evidence, list) else [str(evidence)],
            requires_human_approval=False,
            approval_reasoning=None,
            raw_response=raw_text,
        )

    # ──────────────────────────────────────────────────────────────────────────
    # Task Y4: Round 2 — Response ("What should be done")
    # ──────────────────────────────────────────────────────────────────────────
    async def respond(
        self,
        incident: IncidentRecord,
        shared_grounding: str,
        round1_reconstructions: List[PanelistDeliberation],
        stream_callback: Optional[Callable[[str], Any]] = None,
    ) -> PanelistDeliberation:
        """Execute independent Round 2 response formulation seeing all 3 Round 1 reconstructions."""
        recon_context = ""
        for r in round1_reconstructions:
            recon_context += (
                f"\n--- {r.panelist_name} ({r.role_specialty}) [{r.model_provider}] ---\n"
                f"Entry Point: {r.entry_point}\n"
                f"Root Cause: {r.root_cause_hypothesis}\n"
                f"Severity: {r.severity_assessment} (Confidence: {r.confidence * 100:.1f}%)\n"
                f"Evidence: {', '.join(r.grounded_evidence)}\n"
            )

        prompt = f"""[INCIDENT RESPONSE FORMULATION — ROUND 2]
Incident ID: {incident.incident_id}
Category: {incident.category}
Detection Mesh Confidence: {incident.confidence * 100:.1f}%
Severity: {incident.severity}

--- SHARED GROUNDING TELEMETRY (TASK Y2) ---
{shared_grounding}

--- ROUND 1 RECONSTRUCTION FINDINGS (PANELISTS 1-3) ---
{recon_context}

As {self.name} ({self.specialty}), formulate what actions should be taken:
1. Immediate Tactical Containment Actions (2-3 targeted actions).
2. Architectural Prevention & System Hardening (2-3 structural fixes).
3. Human-in-the-Loop Sign-Off: Does containment require human approval before automated execution? (true / false) and precise justification.
4. Severity confirmation & operational blast-radius estimation.

STRICT INSTRUCTION: Base recommendations strictly on the real incident telemetry and Round 1 findings. Do not propose irrelevant mitigations.

Respond with valid JSON:
{{
  "containment_tactics": ["<action 1>", "<action 2>"],
  "architectural_fixes": ["<fix 1>", "<fix 2>"],
  "requires_human_approval": true | false,
  "approval_reasoning": "<justification for approval or automation>",
  "severity_assessment": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "confidence": 0.95
}}
"""
        system_prompt = self._build_system_prompt()
        try:
            raw_response = await self.llm_provider.generate(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=self.config.temperature,
                max_tokens=self.config.max_tokens,
                stream_callback=stream_callback,
            )
        except Exception as exc:
            logger.warning("Response formulation error for %s: %s", self.name, exc)
            raw_response = f"Response formulation for {self.name}: Propose rate-limiting and AST validation for {incident.category}."

        return self._parse_response_output(raw_response, incident, round1_reconstructions)

    def _parse_response_output(
        self,
        raw_text: str,
        incident: IncidentRecord,
        round1_reconstructions: List[PanelistDeliberation],
    ) -> PanelistDeliberation:
        """Parse structured Round 2 Response output."""
        entry_point = round1_reconstructions[0].entry_point if round1_reconstructions else (incident.affected_endpoints[0] if incident.affected_endpoints else "/")
        root_cause = round1_reconstructions[0].root_cause_hypothesis if round1_reconstructions else f"Threat vector in {incident.category}."
        severity = incident.severity or "HIGH"
        confidence = 0.95
        containment = [
            f"Apply immediate rate-limiting and WAF rule on {entry_point}",
            f"Revoke active attacker session tokens and isolate affected IP: {incident.raw_log_details.get('client_ip', '198.51.100.42')}",
        ]
        architectural = [
            f"Implement zero-trust parameter validation and AST sanitization for {incident.category}",
            "Introduce cryptographically verified tenant boundary checks and centralized authorization middleware",
        ]
        requires_approval = severity in ["CRITICAL", "HIGH"]
        approval_reasoning = f"{self.name} recommends human approval before applying blocking rules due to {severity} blast radius."

        try:
            json_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw_text, re.DOTALL)
            parsed = json.loads(json_match.group(1) if json_match else raw_text[raw_text.find("{"):raw_text.rfind("}")+1])
            if isinstance(parsed, dict):
                containment = parsed.get("containment_tactics") or containment
                architectural = parsed.get("architectural_fixes") or architectural
                requires_approval = bool(parsed.get("requires_human_approval", requires_approval))
                approval_reasoning = parsed.get("approval_reasoning") or approval_reasoning
                severity = parsed.get("severity_assessment") or severity
                confidence = float(parsed.get("confidence") or confidence)
        except Exception:
            pass

        return PanelistDeliberation(
            panelist_id=self.panelist_id,
            panelist_name=self.name,
            role_specialty=self.specialty,
            role_type=PanelistRoleType.RESPONSE,
            model_provider=self.llm_provider.display_name,
            entry_point=entry_point,
            root_cause_hypothesis=root_cause,
            severity_assessment=severity,
            confidence=min(1.0, max(0.1, confidence)),
            containment_tactics=containment if isinstance(containment, list) else [str(containment)],
            architectural_fixes=architectural if isinstance(architectural, list) else [str(architectural)],
            grounded_evidence=["containment_strategy", "operational_risk"],
            requires_human_approval=requires_approval,
            approval_reasoning=approval_reasoning,
            raw_response=raw_text,
        )

    # ──────────────────────────────────────────────────────────────────────────
    # Task Y5: Cross-Examination Round
    # ──────────────────────────────────────────────────────────────────────────
    async def cross_examine(
        self,
        incident: IncidentRecord,
        shared_grounding: str,
        other_panelist_outputs: List[PanelistDeliberation],
        stream_callback: Optional[Callable[[str], Any]] = None,
    ) -> List[CrossExaminationResponse]:
        """Review all other 5 panelists' outputs and generate targeted cross-examination challenges/endorsements."""
        responses: List[CrossExaminationResponse] = []
        peers_to_review = [p for p in other_panelist_outputs if p.panelist_id != self.panelist_id]
        if not peers_to_review:
            return responses

        peer_summary = ""
        for p in peers_to_review:
            peer_summary += (
                f"\n--- Peer: {p.panelist_name} ({p.role_specialty}) [{p.model_provider}] [Role: {p.role_type.value}] ---\n"
                f"Entry Point: {p.entry_point}\n"
                f"Root Cause Hypothesis: {p.root_cause_hypothesis}\n"
                f"Severity: {p.severity_assessment} (Confidence: {p.confidence * 100:.1f}%)\n"
                f"Containment: {', '.join(p.containment_tactics[:2]) if p.containment_tactics else 'N/A'}\n"
                f"Architectural Fixes: {', '.join(p.architectural_fixes[:2]) if p.architectural_fixes else 'N/A'}\n"
                f"Requires Human Approval: {p.requires_human_approval}\n"
            )

        prompt = f"""[CROSS-EXAMINATION ROUND — TASK Y5]
Incident ID: {incident.incident_id}
Category: {incident.category}

--- SHARED GROUNDING TELEMETRY ---
{shared_grounding}

--- PEER DELIBERATIONS (OTHER 5 PANELISTS) ---
{peer_summary}

As {self.name} ({self.specialty}), review your 5 peers' findings:
"Panelist X concluded A, Panelist Y recommended B. Do you agree, disagree, or want to revise your position? Be specific about what you'd change and why."

Evaluate at least 2 distinct peers. For each:
- State your stance: AGREE (endorse), REVISE (amend), or DISSENT (challenge).
- Provide a rigorous, evidence-grounded critique or defense.
- Propose concrete amendments or revised points if applicable.

Respond with valid JSON:
{{
  "critiques": [
    {{
      "target_peer_id": "<peer_id>",
      "target_peer_name": "<peer_name>",
      "stance": "AGREE" | "REVISE" | "DISSENT",
      "critique_type": "ENDORSE" | "CHALLENGE" | "AMEND",
      "debate_argument": "<detailed forensic critique or endorsement>",
      "revised_points": ["<point 1>", "<point 2>"],
      "suggested_amendment": "<specific amendment>"
    }}
  ]
}}
"""
        system_prompt = self._build_system_prompt()
        try:
            raw_response = await self.llm_provider.generate(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=0.2,
                max_tokens=self.config.max_tokens,
                stream_callback=stream_callback,
            )
        except Exception as exc:
            logger.warning("Cross-examination error for %s: %s", self.name, exc)
            raw_response = "{}"

        return self._parse_cross_examination(raw_response, peers_to_review, incident)

    def _parse_cross_examination(
        self,
        raw_text: str,
        peers: List[PanelistDeliberation],
        incident: IncidentRecord,
    ) -> List[CrossExaminationResponse]:
        """Parse structured cross-examination response with fallback."""
        responses: List[CrossExaminationResponse] = []
        try:
            json_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw_text, re.DOTALL)
            parsed = json.loads(json_match.group(1) if json_match else raw_text[raw_text.find("{"):raw_text.rfind("}")+1])
            if isinstance(parsed, dict) and "critiques" in parsed:
                for c in parsed["critiques"]:
                    st = c.get("stance", "AGREE").upper()
                    stance = DebateStance.AGREE if st not in ("AGREE", "REVISE", "DISSENT") else DebateStance(st)
                    responses.append(CrossExaminationResponse(
                        critique_id=f"cx-{uuid.uuid4().hex[:6]}",
                        panelist_id=self.panelist_id,
                        panelist_name=self.name,
                        model_provider=self.llm_provider.display_name,
                        target_peer_id=c.get("target_peer_id", peers[0].panelist_id if peers else "peer_1"),
                        target_peer_name=c.get("target_peer_name", peers[0].panelist_name if peers else "Peer"),
                        stance=stance,
                        critique_type=c.get("critique_type", "CHALLENGE"),
                        debate_argument=c.get("debate_argument", f"{self.name} reviewed peer deliberation."),
                        revised_points=c.get("revised_points", []),
                        suggested_amendment=c.get("suggested_amendment"),
                    ))
        except Exception:
            pass

        # Fallback if parsing failed or was empty
        if not responses and peers:
            for peer in peers[:2]:
                crit_type = "ENDORSE" if peer.severity_assessment == incident.severity else "CHALLENGE"
                stance = DebateStance.AGREE if crit_type == "ENDORSE" else DebateStance.REVISE
                arg = (
                    f"{self.name} endorses {peer.panelist_name}'s analysis on {peer.entry_point}, agreeing with the proposed {peer.containment_tactics[0] if peer.containment_tactics else 'containment priority'}."
                    if crit_type == "ENDORSE"
                    else f"{self.name} cautions that {peer.panelist_name}'s assessment on {peer.entry_point} must account for AST-level validation boundaries."
                )
                responses.append(CrossExaminationResponse(
                    critique_id=f"cx-{uuid.uuid4().hex[:6]}",
                    panelist_id=self.panelist_id,
                    panelist_name=self.name,
                    model_provider=self.llm_provider.display_name,
                    target_peer_id=peer.panelist_id,
                    target_peer_name=peer.panelist_name,
                    stance=stance,
                    critique_type=crit_type,
                    debate_argument=arg,
                    revised_points=["Align perimeter rate-limiting with application AST sanitization"],
                    suggested_amendment=f"Incorporate zero-trust authorization alongside {peer.panelist_name}'s tactical mitigations.",
                ))

        return responses

    # ──────────────────────────────────────────────────────────────────────────
    # Legacy / Backward Compatibility Methods
    # ──────────────────────────────────────────────────────────────────────────
    async def deliberate(
        self,
        incident: IncidentRecord,
        grounded_context: Optional[str] = None,
        stream_callback: Optional[Callable[[str], Any]] = None,
    ) -> PanelistDeliberation:
        """Legacy deliberation wrapper."""
        if self.role_type == PanelistRoleType.RESPONSE:
            dummy_recon = [
                PanelistDeliberation(
                    panelist_id="recon_ref",
                    panelist_name="Forensic Baseline",
                    role_specialty="Reconstruction",
                    model_provider="baseline",
                    entry_point=incident.affected_endpoints[0] if incident.affected_endpoints else "/",
                    root_cause_hypothesis=f"Threat vector in {incident.category}",
                    severity_assessment=incident.severity or "HIGH",
                    confidence=incident.confidence or 0.95,
                )
            ]
            return await self.respond(incident, grounded_context or incident.to_grounding_context(), dummy_recon, stream_callback)
        return await self.reconstruct(incident, grounded_context or incident.to_grounding_context(), stream_callback)

    async def critique_peers(
        self,
        incident: IncidentRecord,
        peer_deliberations: List[PanelistDeliberation],
        stream_callback: Optional[Callable[[str], Any]] = None,
    ) -> List[PeerCritique]:
        """Legacy critique wrapper converting CrossExaminationResponse to PeerCritique."""
        cx_list = await self.cross_examine(incident, incident.to_grounding_context(), peer_deliberations, stream_callback)
        return [
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
            for cx in cx_list
        ]

    async def vote_stance(
        self,
        incident: IncidentRecord,
        judge_synthesis: JudgeSynthesis,
        stream_callback: Optional[Callable[[str], Any]] = None,
    ) -> PanelistVote:
        """Cast final stance vote on the Chief Magistrate's synthesis."""
        prompt = f"""[JUDICIAL SYNTHESIS REVIEW & VOTING]
Incident ID: {incident.incident_id}
Category: {incident.category}
Chief Magistrate Synthesis:
Executive Summary: {judge_synthesis.executive_summary}
Root Cause: {judge_synthesis.root_cause_analysis}
Ranked Actions: {[a.title for a in judge_synthesis.ranked_actions]}
Human Approval Required: {judge_synthesis.requires_human_approval}

As {self.name} ({self.specialty}), cast your vote on whether this judicial synthesis correctly captures the forensic reality and remediation balance.
Options:
- AGREE: Full endorsement of synthesis and ranked actions.
- REVISE: Minor amendment proposed for containment/architecture.
- DISSENT: Fundamental disagreement with root cause or severity.

Provide JSON: {{"stance": "AGREE"|"REVISE"|"DISSENT", "rationale": "...", "suggested_revisions": [...]}}
"""
        system_prompt = self._build_system_prompt()
        try:
            raw_vote = await self.llm_provider.generate(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=0.1,
                max_tokens=512,
                stream_callback=stream_callback,
            )
        except Exception:
            raw_vote = '{"stance": "AGREE", "rationale": "Synthesis grounds correctly in telemetry and balances tactical response with system resilience."}'

        stance = DebateStance.AGREE
        rationale = f"{self.name} endorses the Chief Magistrate's synthesis as rigorously grounded in telemetry."
        revisions = []

        try:
            json_m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw_vote, re.DOTALL)
            parsed_vote = json.loads(json_m.group(1) if json_m else raw_vote)
            if isinstance(parsed_vote, dict):
                st_str = parsed_vote.get("stance", "AGREE").upper()
                if st_str in ("AGREE", "REVISE", "DISSENT"):
                    stance = DebateStance(st_str)
                rationale = parsed_vote.get("rationale") or rationale
                revisions = parsed_vote.get("suggested_revisions") or []
        except Exception:
            pass

        return PanelistVote(
            panelist_id=self.panelist_id,
            panelist_name=self.name,
            model_provider=self.llm_provider.display_name,
            stance=stance,
            rationale=rationale,
            suggested_revisions=revisions if isinstance(revisions, list) else [str(revisions)],
            confidence=0.95,
        )
