"""
Unit tests for CouncilDebateEngine and Multi-Agent Debate Revision Protocol.
"""

import asyncio
import os
import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.council import CouncilDebateEngine
from llm.mock_provider import MockLLMProvider
from schemas.incident import IncidentRecord, TimelineEvent
from schemas.report import DebateStance, RevisionFeedback, AgentRole
from streaming.broadcast import CouncilBroadcaster, EventBus, WebSocketManager


class MockWebSocket:
    def __init__(self):
        self.sent_messages = []

    async def accept(self):
        pass

    async def send_json(self, payload):
        self.sent_messages.append(payload)



def create_sample_incident() -> IncidentRecord:
    return IncidentRecord(
        incident_id="INC-2026-9041-02",
        timestamp="2026-09-04T12:00:00Z",
        category="SQLi",
        severity="CRITICAL",
        confidence=0.96,
        contributing_branch_scores={
            "statistical_anomaly": 0.91,
            "semantic_payload_evaluator": 0.98,
            "stateful_sequence_tracker": 0.85,
        },
        raw_log_details={
            "endpoint": "/api/v1/search",
            "method": "POST",
            "status_code": 500,
            "source_ip": "203.0.113.19",
            "payload_snippet": "' UNION SELECT username, password_hash FROM users --",
        },
        timeline_events=[
            TimelineEvent(
                timestamp="2026-09-04T11:59:00Z",
                action="POST /api/v1/search",
                source_ip="203.0.113.19",
                status_code=500,
                payload_summary="SQL syntax error generated in DB layer",
            )
        ],
        affected_endpoints=["/api/v1/search"],
        affected_entities=["database:users_table"],
    )


@pytest.mark.asyncio
async def test_council_debate_engine_full_run():
    ws_mgr = WebSocketManager()
    bus = EventBus()
    broadcaster = CouncilBroadcaster(websocket_manager=ws_mgr, event_bus=bus)

    ws_client = MockWebSocket()
    await ws_mgr.connect(ws_client)

    # Instantiate council engine with 3 distinct providers
    p1 = MockLLMProvider(model_name="claude-3-5-sonnet", provider_label="anthropic")
    p2 = MockLLMProvider(model_name="gpt-4o", provider_label="openai")
    p3 = MockLLMProvider(model_name="gemini-1.5-pro", provider_label="gemini")

    engine = CouncilDebateEngine(
        broadcaster=broadcaster,
        reconstruction_provider=p1,
        response_provider=p2,
        judge_provider=p3,
    )

    incident = create_sample_incident()
    report = await engine.run_council_debate(incident)

    # 1. Assertions on Final Report
    assert report.incident_id == incident.incident_id
    assert report.incident_category == "SQLi"
    assert len(report.executive_summary) > 0
    assert len(report.technical_timeline) >= 2
    assert len(report.ranked_actions) >= 1
    assert isinstance(report.requires_human_approval, bool)

    # 2. Assertions on Multi-Agent Debate Revision Round
    assert len(report.debate_revisions) == 2
    for rev in report.debate_revisions:
        assert rev.stance in [DebateStance.AGREE, DebateStance.REVISE, DebateStance.DISSENT]
        assert len(rev.rationale) > 0

    # 3. Assertions on Consensus Metric
    assert report.consensus_metric.status in ["FULL_CONSENSUS", "STRONG_CONSENSUS", "PARTIAL_CONSENSUS", "DISSENT"]
    assert 0.0 <= report.consensus_metric.consensus_score <= 1.0

    # 4. Assertions on Participating Models
    assert report.participating_models[AgentRole.RECONSTRUCTION.value] == "anthropic:claude-3-5-sonnet"
    assert report.participating_models[AgentRole.RESPONSE.value] == "openai:gpt-4o"
    assert report.participating_models[AgentRole.JUDGE.value] == "gemini:gemini-1.5-pro"

    # 5. Assertions on WebSocket Stream Broadcasts
    event_types = [m["event_type"] for m in ws_client.sent_messages]
    assert "phase_change" in event_types
    assert "agent_stream" in event_types
    assert "agent_response" in event_types
    assert "debate_revision" in event_types
    assert "council_verdict" in event_types
    assert "council_complete" in event_types


@pytest.mark.asyncio
async def test_consensus_calculation_logic():
    engine = CouncilDebateEngine(force_mock=True)

    # Full consensus
    rev_full = [
        RevisionFeedback(agent_role=AgentRole.RECONSTRUCTION, model_provider="m1", stance=DebateStance.AGREE, rationale="ok"),
        RevisionFeedback(agent_role=AgentRole.RESPONSE, model_provider="m2", stance=DebateStance.AGREE, rationale="ok"),
    ]
    c_full = engine._calculate_consensus(rev_full)
    assert c_full.status == "FULL_CONSENSUS"
    assert c_full.consensus_score == 1.0

    # Strong consensus with 1 revise
    rev_strong = [
        RevisionFeedback(agent_role=AgentRole.RECONSTRUCTION, model_provider="m1", stance=DebateStance.AGREE, rationale="ok"),
        RevisionFeedback(agent_role=AgentRole.RESPONSE, model_provider="m2", stance=DebateStance.REVISE, rationale="refine"),
    ]
    c_strong = engine._calculate_consensus(rev_strong)
    assert c_strong.status == "STRONG_CONSENSUS"
    assert c_strong.consensus_score == 0.88

    # Dissent
    rev_dissent = [
        RevisionFeedback(agent_role=AgentRole.RECONSTRUCTION, model_provider="m1", stance=DebateStance.DISSENT, rationale="disagree"),
        RevisionFeedback(agent_role=AgentRole.RESPONSE, model_provider="m2", stance=DebateStance.AGREE, rationale="ok"),
    ]
    c_dissent = engine._calculate_consensus(rev_dissent)
    assert c_dissent.status == "DISSENT"
    assert c_dissent.consensus_score < 0.7



if __name__ == "__main__":
    asyncio.run(test_council_debate_engine_full_run())
    asyncio.run(test_consensus_calculation_logic())
    print("All Debate Engine unit tests passed successfully!")
