"""
Unit and Integration Tests for MADDY Conversational Assistant (Task L4).
Tests intent classification, multi-engine grounding, WebSocket streaming,
and interactive inline incident card generation.
"""

import asyncio
import json
import pytest
from pathlib import Path

from assistant.agent import MaddyAssistantEngine
from assistant.intent import IntentClassifier
from assistant.models import (
    AssistantIntentType,
    AssistantQuery,
    AssistantResponse,
    AssistantStreamEvent,
)
from database import SharedProductDatabase
from grounding.retriever import GroundingRetriever
from llm.mock_provider import MockLLMProvider


@pytest.fixture
def temp_db(tmp_path):
    db_file = tmp_path / "test_assistant_db.db"
    return SharedProductDatabase(db_path=str(db_file))


def test_intent_classification():
    """Test natural language intent classification across all 5 operational categories."""
    # 1. Incident specific
    intents1 = IntentClassifier.classify("Why did incident INC-2026-99 get flagged as SSRF?")
    assert AssistantIntentType.INCIDENT_SPECIFIC in intents1

    # 2. Aggregate statistics
    intents2 = IntentClassifier.classify("How many SQLi attempts occurred this week?")
    assert AssistantIntentType.AGGREGATE_STATS in intents2

    # 3. System health
    intents3 = IntentClassifier.classify("Is the detection mesh healthy and are all branches online?")
    assert AssistantIntentType.SYSTEM_HEALTH in intents3

    # 4. Model performance
    intents4 = IntentClassifier.classify("What is the accuracy rate and hallucination metric in Phase F?")
    assert AssistantIntentType.MODEL_PERFORMANCE in intents4

    # 5. Multi-intent question
    intents5 = IntentClassifier.classify("Is the mesh healthy and why did incident #1042 occur?")
    assert AssistantIntentType.SYSTEM_HEALTH in intents5
    assert AssistantIntentType.INCIDENT_SPECIFIC in intents5


@pytest.mark.asyncio
async def test_maddy_grounded_aggregate_streaming(temp_db):
    """Test MADDY conversational streaming response grounded in real SQL aggregate statistics."""
    # Seed 2 reports
    for idx in range(2):
        temp_db.save_incident_report({
            "report_id": f"REP-AGG-{idx}",
            "incident_id": f"INC-AGG-{idx}",
            "org_id": "org_cyber",
            "executive_summary": "SQL injection detected on auth endpoint",
            "incident_category": "SQLI",
            "detection_mesh_confidence": 0.96,
            "consensus_metric": {"status": "FULL_CONSENSUS", "consensus_score": 1.0},
            "risk_assessment": {"score": 8.5, "severity_band": "HIGH"},
            "requires_human_approval": False,
            "root_cause": "Unsanitized user input",
        }, org_id="org_cyber")

    retriever = GroundingRetriever(db=temp_db)
    mock_llm = MockLLMProvider(model_name="maddy-test", simulate_delay=0.0)
    engine = MaddyAssistantEngine(retriever=retriever, db=temp_db, llm_provider=mock_llm)

    events: list[AssistantStreamEvent] = []

    async def event_collector(evt: AssistantStreamEvent):
        events.append(evt)

    query = AssistantQuery(
        query="How many SQLi incidents occurred this week?",
        user_id="analyst_jane",
        org_id="org_cyber",
    )

    response = await engine.process_query_stream(query=query, event_callback=event_collector)

    assert response.is_grounded is True
    assert "2" in response.answer or "SQL" in response.answer
    assert any(e.type == "intent_classified" for e in events)
    assert any(e.type == "retrieval_complete" for e in events)
    assert any(e.type == "token" for e in events)
    assert any(e.type == "done" for e in events)

    # Check conversation history in DB
    history = temp_db.get_conversation_history(response.conversation_id, org_id="org_cyber")
    assert len(history) == 2  # 1 user + 1 assistant
    assert history[0]["role"] == "user"
    assert history[1]["role"] == "assistant"


@pytest.mark.asyncio
async def test_maddy_inline_incident_card_detection(temp_db):
    """Test that referencing an incident ID yields structured InlineIncidentCard objects for the UI."""
    temp_db.save_incident_report({
        "report_id": "REP-INC-2026-AFEBE9",
        "incident_id": "INC-2026-AFEBE9",
        "org_id": "org_default",
        "executive_summary": "Remote Code Execution via doc injection on /api/v1/doc",
        "incident_category": "RCE",
        "detection_mesh_confidence": 0.99,
        "consensus_metric": {"status": "FULL_CONSENSUS", "consensus_score": 1.0},
        "risk_assessment": {"score": 9.9, "severity_band": "CRITICAL"},
        "requires_human_approval": True,
        "root_cause": "Shell metacharacters allowed in upload filename",
    }, org_id="org_default")

    retriever = GroundingRetriever(db=temp_db)
    mock_llm = MockLLMProvider(model_name="maddy-test", simulate_delay=0.0)
    engine = MaddyAssistantEngine(retriever=retriever, db=temp_db, llm_provider=mock_llm)

    query = AssistantQuery(
        query="Explain incident INC-2026-AFEBE9 and what the Council concluded",
        org_id="org_default",
    )

    response = await engine.process_query_stream(query=query)
    assert response.is_grounded is True
    assert len(response.inline_incidents) >= 1
    card = response.inline_incidents[0]
    assert card.incident_id == "INC-2026-AFEBE9"
    assert card.category == "RCE"
    assert card.severity == "CRITICAL"
    assert card.risk_score == 9.9


@pytest.mark.asyncio
async def test_maddy_mesh_health_and_honest_negative(temp_db):
    """Test system health inquiry and honest negative when query refers to non-existent data."""
    retriever = GroundingRetriever(db=temp_db)
    mock_llm = MockLLMProvider(model_name="maddy-test", simulate_delay=0.0)
    engine = MaddyAssistantEngine(retriever=retriever, db=temp_db, llm_provider=mock_llm)

    # 1. Mesh health
    health_resp = await engine.process_query_stream(
        AssistantQuery(query="Is the detection mesh healthy right now?")
    )
    assert "ONLINE" in health_resp.answer.upper() or "HEALTHY" in health_resp.answer.upper()

    # 2. Honest negative
    neg_resp = await engine.process_query_stream(
        AssistantQuery(query="Why did mysterious alien incident INC-99999999 crash the database?")
    )
    assert neg_resp.is_grounded is True or "no matching records" in neg_resp.answer.lower()


def test_assistant_fastapi_endpoints():
    """Test REST and WebSocket endpoints in FastAPI app."""
    from fastapi.testclient import TestClient
    from app import app

    client = TestClient(app)

    # 1. REST Endpoint
    resp = client.post("/api/v1/assistant/chat", json={
        "query": "Is everything healthy right now?",
        "user_id": "analyst_test",
        "org_id": "org_default"
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "conversation_id" in data
    assert "answer" in data
    assert data["is_grounded"] is True

    # 2. Conversations List
    conv_resp = client.get("/api/v1/assistant/conversations?org_id=org_default")
    assert conv_resp.status_code == 200
    assert isinstance(conv_resp.json(), list)

    # 3. WebSocket Connection & Streaming
    with client.websocket_connect("/ws/assistant") as ws:
        ws.send_text(json.dumps({
            "query": "What is our Phase F accuracy benchmark?",
            "conversation_id": data["conversation_id"],
            "org_id": "org_default"
        }))
        events = []
        while True:
            msg = ws.receive_text()
            evt = json.loads(msg)
            events.append(evt)
            if evt.get("type") == "done":
                break

        assert any(e.get("type") == "intent_classified" for e in events)
        assert any(e.get("type") == "token" for e in events)
        done_evt = [e for e in events if e.get("type") == "done"][0]
        assert "100" in done_evt.get("full_text", "") or "accuracy" in done_evt.get("full_text", "").lower()


@pytest.mark.asyncio
async def test_maddy_proactive_alert_broadcast(temp_db, tmp_path):
    """Test Task L5 proactive event-driven alert broadcast when Council processes a HIGH/CRITICAL incident."""
    from decisions.decision_manager import DecisionManager

    retriever = GroundingRetriever(db=temp_db)
    mock_llm = MockLLMProvider(model_name="maddy-test", simulate_delay=0.0)
    dec_mgr = DecisionManager(data_dir=str(tmp_path))
    engine = MaddyAssistantEngine(retriever=retriever, db=temp_db, llm_provider=mock_llm, decision_manager=dec_mgr)

    mock_report = {
        "incident_id": "INC-2026-CRIT-01",
        "report_id": "REP-INC-2026-CRIT-01",
        "incident_category": "RCE",
        "risk_assessment": {"score": 9.2, "severity_band": "CRITICAL"},
        "risk_score": 9.2,
        "risk_severity_band": "CRITICAL",
        "requires_human_approval": True,
        "human_approval_reasoning": "Deploying hot-patch rule to block payload pattern requires operator confirmation.",
        "ranked_actions": [
            {
                "action_id": "ACT-01",
                "priority": "P1_HIGH",
                "category": "ARCHITECTURAL_PREVENTION",
                "title": "Apply Input Sanitization Regex Filter",
                "description": "Block incoming parameters matching $(...) pattern.",
                "target_component": "WAF & API Gateway",
                "requires_human_approval": True,
                "approval_reasoning": "Filter rule could impact malformed legacy requests.",
            }
        ],
        "reconstruction_findings": {"entry_point": "/api/v1/execute"},
    }

    alert = await engine.broadcast_proactive_alert(mock_report, org_id="org_default")

    assert alert.incident_id == "INC-2026-CRIT-01"
    assert alert.risk_score == 9.2
    assert alert.severity == "CRITICAL"
    assert alert.requires_human_approval is True
    assert len(alert.pending_actions) == 1
    assert alert.pending_actions[0].action_id == "ACT-01"
    assert "RCE" in alert.message

    # Verify conversation memory was created
    convs = temp_db.list_user_conversations(user_id="soc_analyst_1", org_id="org_default")
    assert len(convs) >= 1
    msgs = temp_db.get_conversation_history(convs[0]["conversation_id"], org_id="org_default")
    assert any("RCE" in m["content"] for m in msgs)


def test_maddy_in_chat_action_decision(temp_db, tmp_path):
    """Test Task L5 in-chat operator action authorization and audit trail persistence."""
    from decisions.decision_manager import DecisionManager
    from assistant.models import DecisionSubmission

    retriever = GroundingRetriever(db=temp_db)
    mock_llm = MockLLMProvider(model_name="maddy-test", simulate_delay=0.0)
    dec_mgr = DecisionManager(data_dir=str(tmp_path))
    engine = MaddyAssistantEngine(retriever=retriever, db=temp_db, llm_provider=mock_llm, decision_manager=dec_mgr)

    # Initialize a conversation turn
    temp_db.create_conversation(user_id="soc_analyst_1", org_id="org_default", title="Test Action Session")

    submission = DecisionSubmission(
        incident_id="INC-2026-CRIT-01",
        report_id="REP-INC-2026-CRIT-01",
        action_id="ACT-01",
        decision="APPROVE",
        analyst_id="soc_analyst_1",
        comments="Approved after reviewing payload signature.",
        org_id="org_default",
    )

    result = engine.handle_action_decision(submission)

    assert result["decision_id"].startswith("DEC-")
    assert result["decision"] == "APPROVED"
    assert result["incident_id"] == "INC-2026-CRIT-01"
    assert result["analyst_id"] == "soc_analyst_1"

    # Verify audit log in decision manager
    history = dec_mgr.list_decisions()
    assert len(history) == 1
    assert history[0].decision_id == result["decision_id"]

    # Verify conversation memory recorded the decision
    convs = temp_db.list_user_conversations(user_id="soc_analyst_1", org_id="org_default")
    msgs = temp_db.get_conversation_history(convs[0]["conversation_id"], org_id="org_default")
    assert any("APPROVED" in m["content"] and "ACT-01" in m["content"] for m in msgs)


def test_grounding_citations_raw_evidence_transparency(temp_db):
    """Test Task L6 'Show Your Work' transparency panel data attached to GroundingCitation."""
    # Seed incident report
    temp_db.save_incident_report({
        "report_id": "REP-TRANSPARENT-01",
        "incident_id": "INC-TRANSPARENT-01",
        "org_id": "org_default",
        "incident_category": "SSRF",
        "detection_mesh_confidence": 0.98,
        "risk_assessment": {"score": 8.1, "severity_band": "HIGH"},
        "executive_summary": "Server-side request forgery attempt on internal metadata API.",
    }, org_id="org_default")

    retriever = GroundingRetriever(db=temp_db)

    # 1. Incident citation raw evidence
    ctx_inc = retriever.retrieve("Explain incident INC-TRANSPARENT-01")
    assert ctx_inc.is_grounded is True
    assert len(ctx_inc.sources_queried) >= 1
    inc_citation = ctx_inc.sources_queried[0]
    assert inc_citation.raw_evidence is not None
    assert inc_citation.raw_evidence.get("incident_id") == "INC-TRANSPARENT-01"

    # 2. Aggregate statistics citation raw evidence
    ctx_agg = retriever.retrieve("How many SSRF incidents occurred this week?")
    assert ctx_agg.is_grounded is True
    agg_citation = [s for s in ctx_agg.sources_queried if s.source_type.value == "AGGREGATE_STATISTICS"][0]
    assert agg_citation.raw_evidence is not None
    assert "total_incidents" in agg_citation.raw_evidence

    # 3. System health citation raw evidence
    ctx_health = retriever.retrieve("Is the detection mesh healthy right now?")
    assert ctx_health.is_grounded is True
    health_citation = [s for s in ctx_health.sources_queried if s.source_type.value == "MESH_HEALTH_TOPOLOGY"][0]
    assert health_citation.raw_evidence is not None
    assert health_citation.raw_evidence.get("gateway_status") == "ONLINE"

    # 4. Model benchmark performance citation raw evidence
    ctx_perf = retriever.retrieve("What is the accuracy rate and hallucination metric in Phase F?")
    assert ctx_perf.is_grounded is True
    perf_citation = [s for s in ctx_perf.sources_queried if s.source_type.value == "MODEL_BENCHMARK_PERF"][0]
    assert perf_citation.raw_evidence is not None
    assert perf_citation.raw_evidence.get("accuracy_rate") == 100.0

