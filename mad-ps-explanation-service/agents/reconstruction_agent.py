"""
Agent 1: Reconstruction Agent ("What happened & why").
Grounded analysis of attack opening, action sequence, and underlying vulnerabilities.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Callable, Optional

from llm.base import BaseLLMProvider
from schemas.incident import IncidentRecord
from schemas.report import ReconstructionResult

logger = logging.getLogger("mad_ps_explanation.agents.reconstruction")

RECONSTRUCTION_SYSTEM_PROMPT = """You are the Lead Cybersecurity Reconstruction Agent for the MAD-PS SOC Council.
Your sole mission is to establish an objective, evidence-grounded factual reconstruction of the security incident.

MANDATORY GROUNDING & ANTI-HALLUCINATION RULES:
1. GROUND EVERY FACT: Every claim you make MUST be directly supported by the fields present in the incident telemetry (e.g. endpoint, parameters, headers, status codes, branch scores).
2. NO INVENTED DETAILS: Do NOT assume or invent unobserved external actions, unlisted IPs, imaginary CVE numbers, or unrecorded database payloads.
3. ADMIT GAPS: If certain details (e.g. precise exfiltration byte count or specific client payload) are not in the raw log, explicitly state that they are unobserved.
4. ROOT CAUSE IDENTIFICATION: Pinpoint the exact architectural or code-level flaw (e.g. Broken Object Level Authorization, unescaped SQL parameter, missing rate limiter, weak token validation) that enabled this vector.

OUTPUT FORMAT:
Respond in valid JSON adhering to this schema:
{
  "entry_point": "<Specific vector / entry point identified directly in raw logs/telemetry>",
  "attack_sequence": [
    "<Step 1: Initial probe / authentication action>",
    "<Step 2: Exploitation action / traversal>",
    "<Step 3: Consequence / observation>"
  ],
  "underlying_condition": "<Specific vulnerability, lack of validation, or architectural condition>",
  "grounded_evidence_fields": [
    "<field_name>: <exact value from record>",
    "<field_name>: <exact value from record>"
  ]
}
"""


class ReconstructionAgent:
    """Agent 1: Reconstructs what happened and why based strictly on raw incident evidence."""

    def __init__(self, llm_provider: BaseLLMProvider) -> None:
        self.llm_provider = llm_provider

    async def analyze(
        self,
        incident: IncidentRecord,
        stream_callback: Optional[Callable[[str], Any]] = None,
        few_shot_context: Optional[str] = None,
    ) -> ReconstructionResult:
        """Run grounded incident reconstruction analysis with optional in-context distillation exemplars."""
        exemplar_block = f"\n{few_shot_context}\n" if few_shot_context else ""
        prompt = (
            f"Please perform a factual, grounded reconstruction of the following incident.\n\n"
            f"{exemplar_block}"
            f"--- INCIDENT TELEMETRY RECORD ---\n"
            f"{incident.to_grounding_context()}\n"
            f"--- END RECORD ---\n\n"
            f"Answer specifically:\n"
            f"1. What was the opening/entry point of this attack?\n"
            f"2. What sequence of actions followed?\n"
            f"3. What underlying condition (missing validation, weak auth, etc.) made it possible?\n"
            f"Ensure every single statement is grounded in the record above."
        )

        raw_output = await self.llm_provider.generate(
            prompt=prompt,
            system_prompt=RECONSTRUCTION_SYSTEM_PROMPT,
            temperature=0.1,
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
            f"The Judge evaluated your reconstruction and the proposed response.\n"
            f"Do you AGREE with the Judge's findings, or do you want to REVISE/DISSENT from their assessment?\n"
            f"Output a JSON object:\n"
            f'{{\n  "stance": "AGREE" | "REVISE" | "DISSENT",\n  "rationale": "<Reasoning for your stance>",\n  "revised_points": ["<Point 1>", "<Point 2>"]\n}}'
        )

        return await self.llm_provider.generate(
            prompt=prompt,
            system_prompt="You are Agent 1 (Reconstruction). Defend the empirical facts of the incident or accept valid judge revisions.",
            temperature=0.2,
            stream_callback=stream_callback,
        )

    def _parse_response(self, incident_id: str, raw_output: str) -> ReconstructionResult:
        """Extract structured JSON from LLM output with robust fallback parsing."""
        try:
            # Try finding JSON block
            json_match = re.search(r"\{.*\}", raw_output, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group(0))
                return ReconstructionResult(
                    incident_id=incident_id,
                    entry_point=data.get("entry_point", "Identified via telemetry logs"),
                    attack_sequence=data.get("attack_sequence", [raw_output[:200]]),
                    underlying_condition=data.get("underlying_condition", "Vulnerability under investigation"),
                    grounded_evidence_fields=data.get("grounded_evidence_fields", []),
                    raw_response=raw_output,
                    model_provider=self.llm_provider.display_name,
                )
        except Exception as exc:
            logger.warning("Failed to parse JSON from ReconstructionAgent output: %s", exc)

        return ReconstructionResult(
            incident_id=incident_id,
            entry_point="Extracted from raw logs",
            attack_sequence=[line.strip() for line in raw_output.split("\n") if line.strip()][:5],
            underlying_condition="Underlying architectural flaw identified in debate",
            grounded_evidence_fields=["raw_logs"],
            raw_response=raw_output,
            model_provider=self.llm_provider.display_name,
        )
