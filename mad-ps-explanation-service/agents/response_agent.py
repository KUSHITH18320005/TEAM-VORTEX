"""
Agent 2: Response Agent ("What should be done").
Formulates immediate containment and architectural prevention recommendations with human-approval gates.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Callable, Optional

from llm.base import BaseLLMProvider
from schemas.incident import IncidentRecord
from schemas.report import ActionPriority, RecommendedAction, ReconstructionResult, ResponsePlan

logger = logging.getLogger("mad_ps_explanation.agents.response")

RESPONSE_SYSTEM_PROMPT = """You are the Principal Security Architect and Incident Response Lead for the MAD-PS SOC Council.
Your goal is to devise actionable, proportionate containment and architectural prevention strategies based on the incident reconstruction.

CORE REQUIREMENTS:
1. IMMEDIATE CONTAINMENT: Practical, fast-acting steps to stop ongoing exfiltration or unauthorized actions (e.g. session revocation, route blocking, dynamic rate limiting).
2. ARCHITECTURAL SYSTEM DESIGN PREVENTION: Do NOT just say "patch it" or "update software". Propose concrete architectural fixes matching the vulnerability category (e.g. for IDOR: "enforce ABAC ownership middleware on /api/v1/user/{id}"; for SQLi: "migrate raw string concatenation to parameterized ORM queries"; for Credential Stuffing: "implement distributed token bucket rate limiting and risk-based MFA step-up").
3. HUMAN-IN-THE-LOOP APPROVAL FLAG:
   - Determine whether remediation steps can execute autonomously or REQUIRE HUMAN APPROVAL before action.
   - Example requiring approval: Blocking an IP subnet shared by real corporate customers or taking a core billing service offline.
   - Example NOT requiring approval: Invalidating a single compromised test token, or applying local rate limiting to an aggressive bot.
   - You MUST output `requires_human_approval: true/false` accompanied by explicit engineering reasoning.

OUTPUT FORMAT:
Respond in valid JSON adhering to this schema:
{
  "immediate_containment": [
    "<Action 1>",
    "<Action 2>"
  ],
  "architectural_prevention": [
    "<Architectural Fix 1>",
    "<Architectural Fix 2>"
  ],
  "requires_human_approval": true | false,
  "human_approval_reasoning": "<Explicit justification for why human intervention is or is not mandatory>",
  "actions": [
    {
      "action_id": "ACT-01",
      "priority": "P0_IMMEDIATE" | "P1_HIGH" | "P2_MEDIUM" | "P3_LOW",
      "category": "CONTAINMENT" | "ARCHITECTURAL_PREVENTION",
      "title": "<Action title>",
      "description": "<Detailed execution description>",
      "target_component": "<Component or Service>",
      "estimated_impact": "<Impact assessment>",
      "requires_human_approval": true | false,
      "approval_reasoning": "<Reason if required>"
    }
  ]
}
"""


class ResponseAgent:
    """Agent 2: Prescribes tactical containment and strategic architectural prevention."""

    def __init__(self, llm_provider: BaseLLMProvider) -> None:
        self.llm_provider = llm_provider

    async def plan_response(
        self,
        incident: IncidentRecord,
        reconstruction: ReconstructionResult,
        stream_callback: Optional[Callable[[str], Any]] = None,
        few_shot_context: Optional[str] = None,
    ) -> ResponsePlan:
        """Formulate response and prevention plan grounded in the reconstruction and few-shot exemplars."""
        exemplar_block = f"\n{few_shot_context}\n" if few_shot_context else ""
        prompt = (
            f"--- INCIDENT TELEMETRY ---\n{incident.to_grounding_context()}\n\n"
            f"{exemplar_block}"
            f"--- AGENT 1 (RECONSTRUCTION) FINDINGS ---\n"
            f"Entry Point: {reconstruction.entry_point}\n"
            f"Attack Sequence:\n" + "\n".join(f"  - {s}" for s in reconstruction.attack_sequence) + "\n"
            f"Underlying Condition: {reconstruction.underlying_condition}\n"
            f"Grounded Evidence: {', '.join(reconstruction.grounded_evidence_fields)}\n"
            f"--- END RECONSTRUCTION ---\n\n"
            f"Please formulate:\n"
            f"1. Immediate containment actions.\n"
            f"2. System-design-level architectural prevention recommendations matching '{incident.category}'.\n"
            f"3. Strict 'requires_human_approval' determination (true/false) with engineering reasoning."
        )

        raw_output = await self.llm_provider.generate(
            prompt=prompt,
            system_prompt=RESPONSE_SYSTEM_PROMPT,
            temperature=0.2,
            stream_callback=stream_callback,
        )

        return self._parse_response(incident.incident_id, raw_output)


    async def review_judge_synthesis(
        self,
        incident: IncidentRecord,
        judge_synthesis_text: str,
        stream_callback: Optional[Callable[[str], Any]] = None,
    ) -> str:
        """Debate Revision Round: Review judge's critique and determine agreement/revision."""
        prompt = (
            f"--- ORIGINAL INCIDENT RECORD ---\n{incident.to_grounding_context()}\n\n"
            f"--- JUDGE'S SYNTHESIS & AUDIT ---\n{judge_synthesis_text}\n--- END JUDGE SYNTHESIS ---\n\n"
            f"The Judge evaluated your response recommendations and human approval thresholds.\n"
            f"Do you AGREE with the Judge's synthesis, or do you want to REVISE/DISSENT from their verdict?\n"
            f"Output a JSON object:\n"
            f'{{\n  "stance": "AGREE" | "REVISE" | "DISSENT",\n  "rationale": "<Reasoning for your stance>",\n  "revised_points": ["<Point 1>", "<Point 2>"]\n}}'
        )

        return await self.llm_provider.generate(
            prompt=prompt,
            system_prompt="You are Agent 2 (Response). Defend your remediation safety and approval thresholds or accept the Judge's improvements.",
            temperature=0.2,
            stream_callback=stream_callback,
        )

    def _parse_response(self, incident_id: str, raw_output: str) -> ResponsePlan:
        """Parse structured response plan with fallback safety."""
        try:
            json_match = re.search(r"\{.*\}", raw_output, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group(0))
                actions = []
                for act in data.get("actions", []):
                    try:
                        actions.append(RecommendedAction(
                            action_id=act.get("action_id", f"ACT-{len(actions)+1:02d}"),
                            priority=ActionPriority(act.get("priority", "P1_HIGH")),
                            category=act.get("category", "CONTAINMENT"),
                            title=act.get("title", "Remediation Action"),
                            description=act.get("description", ""),
                            target_component=act.get("target_component", "Core Service"),
                            estimated_impact=act.get("estimated_impact", "Standard"),
                            requires_human_approval=bool(act.get("requires_human_approval", False)),
                            approval_reasoning=act.get("approval_reasoning"),
                        ))
                    except Exception:
                        pass

                return ResponsePlan(
                    incident_id=incident_id,
                    immediate_containment=data.get("immediate_containment", ["Apply network isolation"]),
                    architectural_prevention=data.get("architectural_prevention", ["Enforce input validation"]),
                    requires_human_approval=bool(data.get("requires_human_approval", False)),
                    human_approval_reasoning=data.get("human_approval_reasoning", "Assessed from operational risk"),
                    actions=actions,
                    raw_response=raw_output,
                    model_provider=self.llm_provider.display_name,
                )
        except Exception as exc:
            logger.warning("Failed to parse JSON from ResponseAgent output: %s", exc)

        return ResponsePlan(
            incident_id=incident_id,
            immediate_containment=["Revoke compromised session token", "Deploy temporary rate limiter"],
            architectural_prevention=["Implement ownership authorization middleware on target routes"],
            requires_human_approval=False,
            human_approval_reasoning="Containment actions are localized to rogue session",
            actions=[],
            raw_response=raw_output,
            model_provider=self.llm_provider.display_name,
        )
