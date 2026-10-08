"""
Unit tests for Council Agents (Reconstruction, Response, Judge).
"""

import asyncio
import os
import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.judge_agent import JudgeAgent
from agents.reconstruction_agent import ReconstructionAgent
from agents.response_agent import ResponseAgent
from llm.mock_provider import MockLLMProvider
from schemas.incident import IncidentRecord, TimelineEvent
from schemas.report import ActionPriority, DebateStance



def create_sample_incident() -> IncidentRecord:
    return IncidentRecord(
        incident_id="INC-2026-9041-01",
        timestamp="2026-09-04T12:00:00Z",
        category="IDOR",
        severity="HIGH",
        confidence=0.92,
        contributing_branch_scores={
            "statistical_anomaly": 0.88,
            "semantic_payload_evaluator": 0.94,
            "stateful_sequence_tracker": 0.79,
        },
        raw_log_details={
            "endpoint": "/api/v1/user/1042/profile",
            "method": "GET",
            "status_code": 200,
            "source_ip": "198.51.100.42",
            "authenticated_sub": "8892",
            "target_service": "user-service",
        },
        campaign_id="CAMP-9041-ALPHA",
        timeline_events=[
            TimelineEvent(
                timestamp="2026-09-04T11:58:00Z",
                action="POST /api/v1/auth/login",
                source_ip="198.51.100.42",
                status_code=200,
                user_id="8892",
            ),
            TimelineEvent(
                timestamp="2026-09-04T12:00:00Z",
                action="GET /api/v1/user/1042/profile",
                source_ip="198.51.100.42",
                status_code=200,
                user_id="8892",
                payload_summary="Queried unowned profile 1042",
            ),
        ],
        affected_endpoints=["/api/v1/user/{id}/profile"],
        affected_entities=["user:1042", "user:8892"],
    )


@pytest.mark.asyncio
async def test_reconstruction_agent():
    incident = create_sample_incident()
    provider = MockLLMProvider(model_name="claude-3-5-sonnet", provider_label="anthropic")
    agent = ReconstructionAgent(provider)

    streamed_chunks = []

    async def stream_cb(chunk):
        streamed_chunks.append(chunk)

    result = await agent.analyze(incident, stream_callback=stream_cb)

    assert result.incident_id == incident.incident_id
    assert "1042" in result.entry_point or "profile" in result.entry_point
    assert len(result.attack_sequence) >= 2
    assert "BOLA" in result.underlying_condition or "IDOR" in result.underlying_condition or "Authorization" in result.underlying_condition
    assert len(result.grounded_evidence_fields) > 0
    assert len(streamed_chunks) > 0


@pytest.mark.asyncio
async def test_response_agent():
    incident = create_sample_incident()
    provider = MockLLMProvider(model_name="gpt-4o", provider_label="openai")
    agent = ResponseAgent(provider)

    # Mock reconstruction
    recon_provider = MockLLMProvider(model_name="claude-3-5-sonnet", provider_label="anthropic")
    recon_agent = ReconstructionAgent(recon_provider)
    recon_result = await recon_agent.analyze(incident)

    plan = await agent.plan_response(incident, recon_result)

    assert plan.incident_id == incident.incident_id
    assert len(plan.immediate_containment) >= 1
    assert len(plan.architectural_prevention) >= 1
    assert isinstance(plan.requires_human_approval, bool)
    assert len(plan.human_approval_reasoning) > 0
    assert len(plan.actions) >= 1


@pytest.mark.asyncio
async def test_judge_agent():
    incident = create_sample_incident()
    recon_agent = ReconstructionAgent(MockLLMProvider(provider_label="anthropic"))
    resp_agent = ResponseAgent(MockLLMProvider(provider_label="openai"))
    judge_agent = JudgeAgent(MockLLMProvider(provider_label="gemini"))

    recon_res = await recon_agent.analyze(incident)
    resp_plan = await resp_agent.plan_response(incident, recon_res)

    synthesis = await judge_agent.synthesize(incident, recon_res, resp_plan)

    assert synthesis.incident_id == incident.incident_id
    assert len(synthesis.factuality_grounding_audit) > 0
    assert len(synthesis.proportionality_audit) > 0
    assert len(synthesis.executive_summary) > 0
    assert len(synthesis.technical_timeline) >= 2
    assert len(synthesis.ranked_actions) >= 1
    assert isinstance(synthesis.requires_human_approval, bool)



if __name__ == "__main__":
    asyncio.run(test_reconstruction_agent())
    asyncio.run(test_response_agent())
    asyncio.run(test_judge_agent())
    print("All Agent unit tests passed successfully!")
